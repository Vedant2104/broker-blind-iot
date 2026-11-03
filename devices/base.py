"""Shared device runtime: MQTT connection, message channel, event log and the
local simulator control API (state / events / send / reset).

The control API is demo harness, not part of the protocol: it lets `bbiot send`
and the dashboard ask a device to act, so device keys never leave the device.
It binds to localhost unless BBIOT_CONTROL_BIND says otherwise (docker).
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import paho.mqtt.client as mqtt

from securelib.channel import Channel, NoGroupKey
from securelib.config import Config, Device
from securelib.groupkeys import CentralizedGroupKeys
from securelib.identity import DeviceKeys
from securelib.log import get_logger
from securelib.message import peek_header
from securelib.mqtt import make_client

# Commands a device may be asked to send, and their argument checks.
ALLOWED_COMMANDS = {"lock", "unlock", "set", "test"}
SETPOINT_RANGE = (5.0, 35.0)


class _Quiet:
    def info(self, *_a: Any, **_k: Any) -> None:
        pass


_QUIET = _Quiet()


class EventLog:
    """Thread-safe ring buffer of what this device saw ("What the device received")."""

    def __init__(self, maxlen: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def add(self, kind: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            event = {"id": next(self._ids), "ts": round(time.time(), 3), "kind": kind, **fields}
            self._items.append(event)
            return event

    def after(self, event_id: int) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._items if e["id"] > event_id]

    @property
    def last_id(self) -> int:
        with self._lock:
            return self._items[-1]["id"] if self._items else 0


class SendError(ValueError):
    pass


def validate_send(cfg: Config, topic: str, cmd: str, args: dict[str, Any]) -> dict[str, Any]:
    """Check a send request against the fixed topic list and command set."""
    if topic not in cfg.topics:
        raise SendError(f"unknown topic {topic!r}")
    dev = cfg.device_for_topic(topic)
    if dev is None or dev.topics.get("cmd") != topic:
        raise SendError(f"{topic!r} is not a command topic")
    if cmd not in ALLOWED_COMMANDS:
        raise SendError(f"unknown command {cmd!r}")
    body: dict[str, Any] = {"cmd": cmd}
    if cmd == "set":
        try:
            setpoint = float(args.get("setpoint"))  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise SendError("'set' needs a numeric setpoint") from exc
        lo, hi = SETPOINT_RANGE
        if not lo <= setpoint <= hi:
            raise SendError(f"setpoint must be between {lo} and {hi}")
        body["setpoint"] = setpoint
    return body


class DeviceBase:
    kind = "base"

    def __init__(self, cfg: Config, dev: Device, mode: str | None = None) -> None:
        self.cfg = cfg
        self.dev = dev
        self.log = get_logger(dev.log_name)
        self.events = EventLog()
        self.lock = threading.RLock()
        self.client: mqtt.Client | None = None
        self.connected = False
        self.reset_state()

        # Identity keys are generated here, on the device, and never leave it.
        key_dir = cfg.device_key_dir(dev.id)
        self.keys, created = DeviceKeys.load_or_create(key_dir, dev.id)
        verb = "generated new" if created else "loaded"
        self.log.info(
            f"{verb} identity keys (Ed25519 + X25519, private keys stay on this device) "
            f"fp={self.keys.fingerprint[:23]}… pairing code {self.keys.pairing_code}"
        )
        from devices.trustwatch import TrustWatch

        self.trust = TrustWatch(self)
        self.group = CentralizedGroupKeys(
            dev.id,
            self.keys.sign_key,
            kdc_key=self.trust.kdc_key,
            publish=self._publish_json,
            may_join=lambda: self.connected and self.trust.trusted,
            on_alert=self.alert,
        )
        self._mode_path = key_dir / "security.json"
        self._keymode_path = key_dir / "keymode.json"
        self.mls = self._build_mls()
        groups = {"centralized": self.group}
        if self.mls is not None:
            groups["decentralized"] = self.mls
        self.channel = Channel(
            dev.id,
            mode or self._load_mode(),
            groups=groups,
            keymode=self._load_keymode(groups),
            signer=self.keys.sign_key,
            peer_key=self.trust.peer_key,
            requires_signature=self._requires_signature,
            seq_path=key_dir / "seq",
            suite=os.environ.get("BBIOT_AEAD", "AES-GCM"),
        )
        self._announced_epoch: int | None = None
        self._last_catch_up = 0.0
        from devices.liveness import Liveness

        self.live = Liveness(self)
        self.log.info(f"security {self.channel.mode.upper()}")

    def _build_mls(self):
        """Decentralized group keys (MLS sidecar), if the bbiot-mls binary is present."""
        from securelib.mls import DecentralizedGroupKeys, MlsError

        device = self

        class LazyDirectory:  # the trust watch builds the HTTPS client on first use
            def __getattr__(self, name: str):
                return getattr(device.trust._verifier_or_build().directory, name)

        try:
            return DecentralizedGroupKeys(
                self.dev.id,
                self.keys.sign_key,
                self.cfg.group_admin,
                publish=self._publish_json,
                certified_key=self.trust.peer_key,
                directory=LazyDirectory(),
                on_alert=self.alert,
                trusted_peers=self.trust.trusted_peers,
                refresh_trust=self.trust.poke,
            )
        except (MlsError, OSError) as exc:
            self.log.info(f"decentralized (MLS) mode unavailable: {exc}")
            return None

    def _load_keymode(self, groups: dict) -> str:
        try:
            mode = json.loads(self._keymode_path.read_text())["keymode"]
        except (OSError, ValueError, KeyError):
            mode = os.environ.get("BBIOT_KEYMODE", "centralized")
        return mode if mode in groups else "centralized"

    def set_keymode(self, keymode: str) -> None:
        if keymode not in self.channel.groups:
            raise ValueError(f"key mode {keymode!r} not available here")
        self.channel.keymode = keymode
        self._keymode_path.write_text(json.dumps({"keymode": keymode}))
        self.log.info(f"key mode {keymode.upper()}")
        self._announced_epoch = None

    def _load_mode(self) -> str:
        try:
            return json.loads(self._mode_path.read_text())["mode"]
        except (OSError, ValueError, KeyError):
            return os.environ.get("BBIOT_SECURITY", "on")

    def _requires_signature(self, topic: str) -> bool:
        """Commands, alarms, heartbeats and acks carry the sender's Ed25519 signature."""
        if topic.startswith(("hb/", "ack/")):
            return True
        return any(
            topic in (d.topics.get("cmd"), d.topics.get("alarm")) for d in self.cfg.devices.values()
        )

    # --- to override -----------------------------------------------------------

    def reset_state(self) -> None:
        """Set the device's initial state."""

    def subscriptions(self) -> list[str]:
        return [t for name, t in self.dev.topics.items() if name == "cmd"]

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        """React to an accepted message."""

    def state(self) -> dict[str, Any]:
        return {}

    def tick(self) -> None:
        """Called every second (simulated physics, timers)."""

    def unacked_alarms(self) -> list[dict[str, Any]]:
        """Alarms nobody acknowledged (reported in heartbeats)."""
        return []

    def on_ack(self, acker: str, body: dict[str, Any]) -> None:
        """An ack addressed to this device arrived."""

    # --- MQTT ----------------------------------------------------------------------

    def publish(
        self, topic: str, body: dict[str, Any], *, retain: bool = False, quiet: bool = False
    ) -> None:
        log = self.channel.log
        if quiet:  # heartbeats/acks: don't flood the log
            self.channel.log = _QUIET
        try:
            payload = self.channel.seal(topic, body)
        except NoGroupKey as exc:
            if not quiet:
                self.log.info(f"not sent on {topic}: {exc}")
            raise
        finally:
            self.channel.log = log
        if self.client is not None:
            self.client.publish(topic, payload, qos=1, retain=retain)
        if not quiet:
            self.events.add("sent", topic=topic, size=len(payload), body=body)

    def publish_state(self) -> None:
        if "state" in self.dev.topics:
            # Without a group key yet, it is republished once one arrives (_housekeeping).
            with contextlib.suppress(NoGroupKey):
                self.publish(self.dev.topics["state"], self.state(), retain=True)

    def _maybe_catch_up(self, payload: bytes) -> None:
        """Traffic under a NEWER epoch means we missed a rekey: ask the KDC again
        (rate-limited). A revoked device is simply refused by the KDC."""
        header = peek_header(payload)
        active = self.channel.group
        current = (active.epoch if active is not None else None) or 0
        if header is None or header.epoch <= current:
            return
        now = time.monotonic()
        if now - self._last_catch_up > 10:
            self._last_catch_up = now
            if header.source == "mls" and self.mls is not None:
                self.log.info(f"saw MLS epoch {header.epoch} > mine ({current}) → catching up")
                self.mls.catch_up()
            elif header.source == "kdc":
                self.log.info(f"saw epoch {header.epoch} > mine ({current}) → asking the KDC")
                self.group.rejoin()

    def _publish_json(self, topic: str, msg: dict, retain: bool = False) -> None:
        """Key-exchange messages: plain JSON, public values only."""
        if self.client is not None:
            payload = json.dumps(msg, separators=(",", ":"))
            self.client.publish(topic, payload, qos=1, retain=retain)

    def _housekeeping(self) -> None:
        self.group.tick()
        self.live.tick()
        if self.mls is not None and self.connected and self.trust.trusted:
            self.mls.tick()
        active = self.channel.group
        epoch = active.epoch if active is not None else None
        if self.channel.mode == "on" and epoch is not None and epoch != self._announced_epoch:
            self._announced_epoch = epoch
            self.publish_state()

    def _on_connect(self, client: mqtt.Client, _u: Any, _f: Any, rc: Any, _p: Any) -> None:
        if rc.is_failure:
            self.log.info(f"broker refused connection: {rc}")
            return
        self.connected = True
        extra = self.mls.subscriptions() if self.mls is not None else []
        extra += self.live.subscriptions()
        for topic in self.subscriptions() + self.group.subscriptions() + extra:
            client.subscribe(topic, qos=1)
        self.log.info(
            f"connected to broker {self.cfg.broker_host}:{self.cfg.broker_port} "
            f"(mTLS as '{self.dev.id}'), subscribed: {', '.join(self.subscriptions()) or '-'}"
        )
        self.publish_state()

    def _on_disconnect(self, *_args: Any) -> None:
        self.connected = False
        self.log.info("disconnected from broker, retrying")

    def _on_message(self, _c: mqtt.Client, _u: Any, msg: mqtt.MQTTMessage) -> None:
        if msg.topic.startswith("kdc/"):
            self.group.handle(msg.topic, msg.payload)
            return
        if msg.topic.startswith("mls/"):
            if self.mls is not None:
                self.mls.handle(msg.topic, msg.payload)
            return
        if msg.topic == "hub/quarantine":
            self.live.on_quarantine_notice(msg.payload)
            return
        opened = self.channel.open(msg.topic, msg.payload)
        if opened.ok:
            denied = self.live.unauthorized(msg.topic, opened.sender)
            if denied:
                opened.ok, opened.reason = False, denied
        if not opened.ok and (opened.reason or "").startswith("wrong epoch"):
            self._maybe_catch_up(msg.payload)
        if not opened.ok:
            self.log.info(f"✗ REJECTED on {msg.topic}: {opened.reason}")
            self.events.add(
                "rejected", topic=msg.topic, size=len(msg.payload), reason=opened.reason
            )
            return
        self.events.add(
            "accepted",
            topic=msg.topic,
            size=len(msg.payload),
            sender=opened.sender,
            seq=opened.seq,
            epoch=opened.epoch,
            signed=opened.signed,
            body=opened.body,
        )
        if self.live.is_spied(msg.topic):
            self.live.spied += 1
            self.log.info(f"☠ (compromised) read {opened.body} on {msg.topic}")
            self.events.add("spied", topic=msg.topic, body=opened.body)
            return
        if msg.topic.startswith("ack/"):
            self.live.on_ack(msg.topic.split("/", 1)[1], opened.body)
            return
        with self.lock:
            self.handle(msg.topic, opened.body, opened.sender, opened.seq)
        if msg.topic == self.dev.topics.get("cmd"):
            self.live.send_ack(msg.topic, opened.sender, opened.seq, opened.body.get("cmd"))

    def start_mqtt(self) -> None:
        client = make_client(self.cfg, self.dev.id)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        client.reconnect_delay_set(1, 5)
        client.connect_async(self.cfg.broker_host, self.cfg.broker_port, keepalive=20)
        client.loop_start()
        self.client = client

    # --- control API -----------------------------------------------------------------

    def send(self, topic: str, cmd: str, args: dict[str, Any]) -> dict[str, Any]:
        body = validate_send(self.cfg, topic, cmd, args)
        self.log.info(f"→ sending cmd={cmd} to {topic}")
        try:
            self.publish(topic, body)
        except NoGroupKey as exc:
            raise SendError(str(exc)) from exc
        self.live.on_sent_command(topic, cmd, self.channel.last_seq)
        return body

    def set_security(self, mode: str) -> None:
        self.channel.mode = mode  # validates
        self._mode_path.write_text(json.dumps({"mode": mode}))
        self.log.info(f"security {mode.upper()}")
        self._announced_epoch = None
        if mode == "off":
            self.publish_state()

    def reset(self) -> None:
        self.live.compromised, self.live.spied = [], 0
        with self.lock:
            self.reset_state()
        self.log.info("reset to initial state")
        self.publish_state()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            state = self.state()
        return {
            "id": self.dev.id,
            "kind": self.kind,
            "label": self.dev.label,
            "connected": self.connected,
            "state": state,
            "security": self.channel.mode,
            "keymode": self.channel.keymode,
            "quarantined": sorted(self.live.quarantine.quarantined),
            "compromised": self.live.compromised,
            "group": (self.channel.group or self.group).status(),
            "groups": {name: g.status() for name, g in self.channel.groups.items()},
            "identity": self.trust.snapshot(),
            "last_event": self.events.last_id,
        }

    def identity(self) -> dict[str, Any]:
        """Public pairing info: the CSR and the code shown on the device (QR)."""
        return {
            "device_id": self.dev.id,
            "csr_pem": self.keys.csr_pem.decode(),
            "pairing_code": self.keys.pairing_code,
            "fingerprint": self.keys.fingerprint,
            "cert": self.trust.own,
        }

    def alert(self, severity: str, title: str, reason: str, **details: Any) -> None:
        self.events.add("alert", severity=severity, title=title, reason=reason, **details)

    def serve_control(self) -> ThreadingHTTPServer:
        device = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:  # keep logs to our format
                pass

            def _json(self, code: int, data: Any) -> None:
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                url = urlparse(self.path)
                if url.path == "/state":
                    return self._json(200, device.snapshot())
                if url.path == "/events":
                    after = int(parse_qs(url.query).get("after", ["0"])[0] or 0)
                    return self._json(200, device.events.after(after))
                if url.path == "/identity":
                    return self._json(200, device.identity())
                return self._json(404, {"error": "not found"})

            def do_POST(self) -> None:
                url = urlparse(self.path)
                length = min(int(self.headers.get("Content-Length") or 0), 4096)
                try:
                    data = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    return self._json(400, {"error": "bad json"})
                if url.path == "/send":
                    try:
                        body = device.send(
                            str(data.get("topic", "")),
                            str(data.get("cmd", "")),
                            dict(data.get("args") or {}),
                        )
                    except SendError as exc:
                        return self._json(422, {"error": str(exc)})
                    return self._json(200, {"sent": body})
                if url.path == "/reset":
                    device.reset()
                    return self._json(200, device.snapshot())
                if url.path == "/security":
                    try:
                        device.set_security(str(data.get("mode", "")))
                    except ValueError as exc:
                        return self._json(422, {"error": str(exc)})
                    return self._json(200, device.snapshot())
                if url.path == "/compromise":
                    topics = [str(t) for t in data.get("subscribe", [])][:10]
                    device.live.compromise(topics)
                    return self._json(200, {"compromised": topics})
                if url.path == "/try-decrypt":
                    try:
                        payload = bytes.fromhex(str(data.get("payload", "")))
                    except ValueError:
                        return self._json(422, {"error": "payload must be hex"})
                    return self._json(200, device.live.try_decrypt(str(data.get("topic")), payload))
                if url.path == "/mls-rejoin":
                    if device.mls is None:
                        return self._json(422, {"error": "MLS not available"})
                    device.mls.request_rejoin(force=True)
                    return self._json(200, {"requested": True})
                if url.path == "/keymode":
                    try:
                        device.set_keymode(str(data.get("keymode", "")))
                    except ValueError as exc:
                        return self._json(422, {"error": str(exc)})
                    return self._json(200, device.snapshot())
                if url.path == "/rejoin":
                    auth = str(data.get("auth", "signed"))
                    if auth not in ("signed", "unsigned"):
                        return self._json(422, {"error": "auth must be signed or unsigned"})
                    device.group.rejoin(auth)
                    return self._json(200, {"rejoin": auth})
                return self._json(404, {"error": "not found"})

        bind = os.environ.get("BBIOT_CONTROL_BIND", "127.0.0.1")
        server = ThreadingHTTPServer((bind, self.dev.control_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.log.info(f"simulator control API on {bind}:{self.dev.control_port}")
        return server

    def run_forever(self) -> None:
        self.serve_control()
        self.trust.start()
        self.start_mqtt()
        while True:
            time.sleep(1)
            with self.lock:
                self.tick()
            self._housekeeping()
