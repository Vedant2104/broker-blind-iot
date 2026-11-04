"""Per-message cost: added bytes and latency, plain MQTT vs TLS only vs ours.

All three go through the same benchmark Mosquitto (plain listener / mTLS listener),
publisher and subscriber in this process (one clock), one message in flight at a time.
"Ours" includes sealing at the sender and every receive check at the subscriber.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bench.common import (
    Emit,
    mqtt_publish_size,
    results_dir,
    summarize,
    tls_overhead,
    write_csv,
)
from securelib.config import Config
from securelib.message import Opener, seal
from securelib.mqtt import make_client

# Representative messages: a thermostat state update (AEAD only) and a phone command
# (AEAD + Ed25519 signature, as every command and alarm carries).
KINDS = {
    "state": ("home/thermostat/living/state", {"temperature": 21.4, "setpoint": 21.5}, False),
    "command": ("home/thermostat/living/cmd", {"cmd": "set", "setpoint": 21.5}, True),
}
SENDER = "phone"


@dataclass
class Codec:
    """How one mode turns a body into a payload and back."""

    mode: str  # plain | tls | ours
    key: bytes
    signer: Ed25519PrivateKey
    seq: int = 0

    def encode(self, topic: str, body: dict, signed: bool) -> bytes:
        self.seq += 1
        if self.mode != "ours":  # what security OFF sends: a plaintext JSON envelope
            env = {"from": SENDER, "seq": self.seq, "ts": round(time.time(), 3), **body}
            return json.dumps(env, separators=(",", ":")).encode()
        raw = json.dumps(body, separators=(",", ":")).encode()
        return seal(
            topic=topic,
            body=raw,
            sender=SENDER,
            seq=self.seq,
            epoch=1,
            group_key=self.key,
            ts_ms=int(time.time() * 1000),
            signer=self.signer if signed else None,
        )


def byte_rows(codec_key: bytes, signer: Ed25519PrivateKey, tls: tuple[str, str]) -> list[dict]:
    """Bytes per message for each mode, payload and on the wire (MQTT + TLS record)."""
    rows = []
    overhead = tls_overhead(*tls)
    for kind, (topic, body, signed) in KINDS.items():
        plain_payload = None
        for mode in ("plain", "tls", "ours"):
            payload = Codec(mode, codec_key, signer).encode(topic, body, signed)
            plain_payload = plain_payload or len(payload)
            packet = mqtt_publish_size(topic, len(payload))
            wire = packet + (overhead if mode != "plain" else 0)
            rows.append(
                {
                    "kind": kind,
                    "mode": mode,
                    "payload_bytes": len(payload),
                    "mqtt_packet_bytes": packet,
                    "wire_bytes": wire,
                    "added_vs_plain": wire - mqtt_publish_size(topic, plain_payload),
                    "tls": f"{tls[0]} {tls[1]}" if mode != "plain" else "none",
                }
            )
    return rows


class _Link:
    """A publisher and a subscriber on one broker listener."""

    def __init__(self, cfg: Config, identity: str, mode: str) -> None:
        self.mode = mode
        self.got = threading.Event()
        self.received: bytes | None = None
        self.topic_prefix = f"bench/{uuid.uuid4().hex[:8]}/"

        def client() -> mqtt.Client:
            if mode == "plain":
                return mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=f"bench-{uuid.uuid4().hex[:8]}",
                )
            return make_client(cfg, identity)

        port = cfg.bench_plain_port if mode == "plain" else cfg.bench_tls_port
        self.pub, self.sub = client(), client()
        subscribed = threading.Event()
        self.sub.on_subscribe = lambda *_a: subscribed.set()
        self.sub.on_message = self._on_message
        for c in (self.pub, self.sub):
            c.connect(cfg.bench_host, port, keepalive=30)
            c.loop_start()
        self.sub.subscribe(self.topic_prefix + "#", qos=1)
        if not subscribed.wait(10):
            raise TimeoutError(f"benchmark broker {cfg.bench_host}:{port} did not answer")

    def _on_message(self, _c, _u, msg: mqtt.MQTTMessage) -> None:
        self.received = msg.payload
        self.on_receive(msg.topic, msg.payload)
        self.got.set()

    def on_receive(self, topic: str, payload: bytes) -> None:  # replaced per run
        pass

    def tls_params(self) -> tuple[str, str]:
        sock = self.pub.socket()
        try:
            return sock.version(), sock.cipher()[0]  # type: ignore[union-attr]
        except AttributeError:
            return ("none", "none")

    def close(self) -> None:
        for c in (self.pub, self.sub):
            c.disconnect()
            c.loop_stop()


def latency_rows(cfg: Config, identity: str, n: int, emit: Emit) -> tuple[list[dict], tuple]:
    key = os.urandom(32)
    signer = Ed25519PrivateKey.generate()
    rows: list[dict] = []
    tls = ("TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384")
    for mode in ("plain", "tls", "ours"):
        link = _Link(cfg, identity, mode)
        if mode == "tls":
            tls = link.tls_params()
        try:
            for kind, (topic, body, signed) in KINDS.items():
                codec = Codec(mode, key, signer)
                opener = Opener(
                    current_key=lambda _s: (1, key),
                    sender_key=lambda _s: signer.public_key(),
                    requires_signature=lambda _t, signed=signed: signed,
                    window=n + 64,
                )
                full_topic = link.topic_prefix + topic

                def receive(t: str, p: bytes, mode=mode, topic=topic, opener=opener) -> None:
                    if mode == "ours":  # every check a device does: tag, topic, replay, time
                        opener.open(topic, p, int(time.time() * 1000))
                    else:
                        json.loads(p)

                link.on_receive = receive
                samples = []
                for _ in range(n):
                    link.got.clear()
                    t0 = time.perf_counter()
                    link.pub.publish(full_topic, codec.encode(topic, body, signed), qos=1)
                    if not link.got.wait(5):
                        raise TimeoutError("message lost on the benchmark broker")
                    samples.append((time.perf_counter() - t0) * 1000)
                s = summarize(samples)
                rows.append(
                    {
                        "mode": mode,
                        "kind": kind,
                        "n": n,
                        "median_ms": s["median"],
                        "p95_ms": s["p95"],
                        "mean_ms": s["mean"],
                    }
                )
                emit(
                    f"[bench]   {mode:<5} {kind:<7} median {s['median']:.3f} ms  "
                    f"p95 {s['p95']:.3f} ms  (n={n})"
                )
        finally:
            link.close()
    return rows, tls


def run(cfg: Config, emit: Emit, *, identity: str, n: int, out: Path | None = None) -> dict:
    out = out or results_dir()
    emit(
        f"[bench] per-message latency: plain MQTT vs TLS only vs ours, n={n} each "
        f"(benchmark broker {cfg.bench_host})"
    )
    lat, tls = latency_rows(cfg, identity, n, emit)
    sizes = byte_rows(os.urandom(32), Ed25519PrivateKey.generate(), tls)
    emit(f"[bench] per-message bytes (TLS: {tls[0]} {tls[1]}):")
    for r in sizes:
        emit(
            f"[bench]   {r['kind']:<7} {r['mode']:<5} payload {r['payload_bytes']:>4} B  "
            f"on the wire {r['wire_bytes']:>4} B  (+{r['added_vs_plain']} vs plain)"
        )
    write_csv(out / "message_latency.csv", lat)
    write_csv(out / "message_bytes.csv", sizes)
    emit(f"[bench] → {(out / 'message_latency.csv').as_posix()}, message_bytes.csv")
    return {"latency": lat, "bytes": sizes}
