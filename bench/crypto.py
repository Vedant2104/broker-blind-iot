"""Crypto operation timings on this machine (run the same command on a Raspberry Pi
to fill the Pi column: `bbiot bench crypto`)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bench.common import Emit, host_info, results_dir, summarize, time_us, write_csv
from securelib.kdcproto import DeviceJoin, KdcJoin, wrap_key
from securelib.message import Opener, seal

TOPIC = "home/thermostat/living/cmd"
BODY = json.dumps({"cmd": "set", "setpoint": 21.5}, separators=(",", ":")).encode()


def _sealed(n: int, key: bytes, signer: Ed25519PrivateKey | None, sender: str) -> list[bytes]:
    now = int(time.time() * 1000)
    return [
        seal(
            topic=TOPIC,
            body=BODY,
            sender=sender,
            seq=i + 1,
            epoch=1,
            group_key=key,
            ts_ms=now,
            signer=signer,
        )
        for i in range(n)
    ]


def _open_all(payloads: list[bytes], key: bytes, pub, signed: bool) -> None:
    opener = Opener(
        current_key=lambda _src: (1, key),
        sender_key=lambda _s: pub,
        requires_signature=lambda _t: signed,
        window=len(payloads) + 64,
    )
    now = int(time.time() * 1000)
    for p in payloads:
        opener.open(TOPIC, p, now)


def run(emit: Emit, n: int = 2000, out: Path | None = None) -> list[dict]:
    info = host_info()
    emit(f"[bench] crypto timings on {info['host']} ({info['machine']}), n={n} per operation")
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    msg64 = os.urandom(64)
    sig = sk.sign(msg64)
    x_a, x_b = X25519PrivateKey.generate(), X25519PrivateKey.generate().public_key()
    key = os.urandom(32)
    aes, chacha = AESGCM(key), ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct_aes, ct_chacha = aes.encrypt(nonce, msg64, b"ad"), chacha.encrypt(nonce, msg64, b"ad")

    def hkdf() -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"bench").derive(key)

    def join_handshake() -> None:
        dev = DeviceJoin("thermostat")
        kdc = KdcJoin.from_hello(dev.hello())
        finish, _ = dev.on_challenge(kdc.challenge(sk), pk, sk)
        kdc.on_finish(finish, pk)

    ops = [
        ("Ed25519 sign (64 B)", lambda: sk.sign(msg64)),
        ("Ed25519 verify (64 B)", lambda: pk.verify(sig, msg64)),
        ("X25519 key agreement", lambda: x_a.exchange(x_b)),
        ("X25519 keygen + agreement", lambda: X25519PrivateKey.generate().exchange(x_b)),
        ("HKDF-SHA256 (32 B)", hkdf),
        ("AES-256-GCM encrypt (64 B)", lambda: aes.encrypt(nonce, msg64, b"ad")),
        ("AES-256-GCM decrypt (64 B)", lambda: aes.decrypt(nonce, ct_aes, b"ad")),
        ("ChaCha20-Poly1305 encrypt (64 B)", lambda: chacha.encrypt(nonce, msg64, b"ad")),
        ("ChaCha20-Poly1305 decrypt (64 B)", lambda: chacha.decrypt(nonce, ct_chacha, b"ad")),
        (
            "seal state message (AEAD)",
            lambda: seal(
                topic=TOPIC,
                body=BODY,
                sender="thermostat",
                seq=1,
                epoch=1,
                group_key=key,
                ts_ms=0,
            ),
        ),
        (
            "seal command (AEAD + Ed25519)",
            lambda: seal(
                topic=TOPIC,
                body=BODY,
                sender="phone",
                seq=1,
                epoch=1,
                group_key=key,
                ts_ms=0,
                signer=sk,
            ),
        ),
        ("KDC key wrap (per member)", lambda: wrap_key(key, "thermostat", 7, key)),
        ("KDC signed join handshake (both sides)", join_handshake),
    ]
    rows = []
    for name, fn in ops:
        reps = n if "handshake" not in name else max(50, n // 10)
        s = summarize(time_us(fn, reps))
        rows.append({**info, "op": name, "n": reps, "median_us": s["median"], "p95_us": s["p95"]})
        emit(f"[bench]   {name:<40} {s['median']:>9.1f} µs (p95 {s['p95']:.1f})")

    # Opening needs a fresh sequence number each time (the replay window would refuse
    # repeats), so pre-seal n messages and time opening all of them.
    for label, signer in (
        ("open state message (all checks)", None),
        ("open command (+ verify)", sk),
    ):
        payloads = _sealed(n, key, signer, "phone")
        t = time.perf_counter_ns()
        _open_all(payloads, key, pk, signer is not None)
        per = (time.perf_counter_ns() - t) / 1000 / n
        rows.append({**info, "op": label, "n": n, "median_us": round(per, 4), "p95_us": ""})
        emit(f"[bench]   {label:<40} {per:>9.1f} µs (mean)")

    tag = info["machine"].lower().replace(" ", "-") or "host"
    path = write_csv(out or results_dir() / f"crypto-{tag}.csv", rows)
    emit(f"[bench] → {path.as_posix()}")
    return rows
