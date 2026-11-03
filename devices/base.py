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
        self.channel = Channel(
            dev.id,
            mode or self._load_mode(),
            group=self.group,
            signer=self.keys.sign_key,
            peer_key=self.trust.peer_key,
            requires_signature=self._requires_signature,
            seq_path=key_dir / "seq",
            suite=os.environ.get("BBIOT_AEAD", "AES-GCM"),
        )
        self._announced_epoch: int | None = None
        self._last_catch_up = 0.0
        self.log.info(f"security {self.channel.mode.upper()}")

    def _load_mode(self) -> str:
        try:
            return json.loads(self._mode_path.read_text())["mode"]
        except (OSError, ValueError, KeyError):
            return os.environ.get("BBIOT_SECURITY", "on")

    def _requires_signature(self, topic: str) -> bool:
        """Commands and alarms carry the sender's Ed25519 signature."""
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

    # --- MQTT ----------------------------------------------------------------------

    def publish(self, topic: str, body: dict[str, Any], *, retain: bool = False) -> None:
        try:
            payload = self.channel.seal(topic, body)
        except NoGroupKey as exc:
            self.log.info(f"not sent on {topic}: {exc}")
            raise
        if self.client is not None:
            self.client.publish(topic, payload, qos=1, retain=retain)
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
        current = self.group.epoch or 0
        if header is None or header.epoch <= current:
            return
        now = time.monotonic()
        if now - self._last_catch_up > 10:
            self._last_catch_up = now
            self.log.info(f"saw epoch {header.epoch} > mine ({current}) → asking the KDC")
            self.group.rejoin()

    def _publish_json(self, topic: str, msg: dict) -> None:
        """Key-exchange messages: plain JSON, public values only."""
        if self.client is not None:
            self.client.publish(topic, json.dumps(msg, separators=(",", ":")), qos=1)

    def _housekeeping(self) -> None:
        self.group.tick()
        epoch = self.group.epoch
        if self.channel.mode == "on" and epoch is not None and epoch != self._announced_epoch:
            self._announced_epoch = epoch
            self.publish_state()

    def _on_connect(self, client: mqtt.Client, _u: Any, _f: Any, rc: Any, _p: Any) -> None:
        if rc.is_failure:
            self.log.info(f"broker refused connection: {rc}")
            return
        self.connected = True
        for topic in self.subscriptions() + self.group.subscriptions():
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
        opened = self.channel.open(msg.topic, msg.payload)
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
        with self.lock:
            self.handle(msg.topic, opened.body, opened.sender, opened.seq)

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
        return body

    def set_security(self, mode: str) -> None:
        self.channel.mode = mode  # validates
        self._mode_path.write_text(json.dumps({"mode": mode}))
        self.log.info(f"security {mode.upper()}")
        self._announced_epoch = None
        if mode == "off":
            self.publish_state()

    def reset(self) -> None:
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
            "group": self.group.status(),
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

    def alert(self, severity: str, title: str, reason: str) -> None:
        self.events.add("alert", severity=severity, title=title, reason=reason)

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
