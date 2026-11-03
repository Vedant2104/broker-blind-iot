"""Every user-visible action, shared by the CLI and the dashboard.

Each function takes an ``emit`` callback that receives human-readable log lines
(printed by the CLI, streamed over WebSocket by the dashboard), so a button
click and the equivalent `bbiot` command produce identical output.
"""

from __future__ import annotations

import json
import shlex
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import paho.mqtt.client as mqtt

from cli import remote
from securelib.config import Config
from securelib.mqtt import address, make_client

Emit = Callable[[str], None]

SUCCEEDED, BLOCKED, DETECTED = "SUCCEEDED", "BLOCKED", "DETECTED"


@dataclass
class AttackResult:
    attack: str
    outcome: str  # SUCCEEDED | BLOCKED | DETECTED
    reason: str
    command: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _say(emit: Emit, msg: str) -> None:
    emit(f"[attacker] {msg}")


def _cmdline(*parts: str) -> str:
    return "bbiot " + " ".join(shlex.quote(p) for p in parts)


def format_payload(payload: bytes, limit: int = 120) -> str:
    """Readable text if the payload is printable UTF-8, otherwise hex."""
    try:
        text = payload.decode("utf-8")
        if text.isprintable():
            return text if len(text) <= limit else text[:limit] + "…"
    except UnicodeDecodeError:
        pass
    hx = payload.hex(" ")
    return "hex: " + (hx if len(hx) <= limit else hx[:limit] + "…")


def _wait_for(predicate: Callable[[], Any], timeout: float = 5.0, step: float = 0.2) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None


def _events_since(cfg: Config, device: str, mark: int, kind: str | None = None, topic=None):
    return [
        e
        for e in remote.device_events(cfg, device, after=mark)
        if (kind is None or e["kind"] == kind) and (topic is None or e.get("topic") == topic)
    ]


def _rejection(cfg: Config, device: str, mark: int) -> str | None:
    rejected = _events_since(cfg, device, mark, kind="rejected")
    return rejected[-1]["reason"] if rejected else None


def _mark(cfg: Config, device: str) -> int:
    return remote.device_state(cfg, device)["last_event"]


def _cmd_topic(cfg: Config, device: str) -> str:
    return cfg.devices[device].topics["cmd"]


# --- send / spy ----------------------------------------------------------------------


def send(cfg: Config, device: str, topic: str, cmd: str, args: dict, emit: Emit) -> dict:
    sent = remote.device_send(cfg, device, topic, cmd, args)
    emit(f"[{cfg.devices[device].log_name}] → sent {json.dumps(sent['sent'])} to {topic}")
    return sent


class Spy:
    """Subscribe to Mosquitto itself and report everything the broker sees."""

    def __init__(
        self,
        cfg: Config,
        topic_filter: str,
        on_message: Callable[[str, bytes], None],
        identity: str = "cli",
    ):
        self.client = make_client(cfg, identity)
        self.topic_filter = topic_filter
        self.ready = threading.Event()
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = lambda *_a: self.ready.set()
        self.client.on_message = lambda _c, _u, m: on_message(m.topic, m.payload)
        host, port = address(cfg, "mosquitto")
        self.client.connect(host, port, keepalive=30)
        self.client.loop_start()

    def _on_connect(self, client: mqtt.Client, *_a: Any) -> None:
        client.subscribe(self.topic_filter, qos=1)

    def close(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()


def spy_line(topic: str, payload: bytes) -> str:
    return f"[spy] {topic}  {len(payload)}B  {format_payload(payload)}"


# --- attacks 1-5 -------------------------------------------------------------------------


def attack_read(cfg: Config, emit: Emit, seconds: float = 3.0) -> AttackResult:
    """1. Broker reads payloads: listen on home/# while the phone locks the front door."""
    command = _cmdline("attack", "read")
    seen: list[tuple[str, bytes]] = []
    spy = Spy(cfg, "home/#", lambda t, p: seen.append((t, p)))
    try:
        spy.ready.wait(5)
        _say(emit, "listening on home/# as the broker...")
        send(cfg, "phone", _cmd_topic(cfg, "front-door"), "lock", {}, emit)
        time.sleep(seconds)
    finally:
        spy.close()

    readable = []
    for topic, payload in seen:
        emit(spy_line(topic, payload))
        try:
            body = json.loads(payload)
            if isinstance(body, dict):
                readable.append((topic, body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if readable:
        topic, body = next(((t, b) for t, b in readable if "cmd" in b), readable[0])
        fields = {k: v for k, v in body.items() if k not in ("ts",)}
        reason = f"broker read {len(readable)}/{len(seen)} payloads, e.g. {topic} {fields}"
        return AttackResult("read", SUCCEEDED, reason, command, {"seen": len(seen)})
    return AttackResult(
        "read", BLOCKED, f"all {len(seen)} payloads were ciphertext", command, {"seen": len(seen)}
    )


def attack_modify(
    cfg: Config, emit: Emit, setpoint: float = 30.0, requested: float = 21.0
) -> AttackResult:
    """2. Broker rewrites the thermostat setpoint in transit."""
    command = _cmdline("attack", "modify", "--setpoint", f"{setpoint:g}")
    topic = _cmd_topic(cfg, "thermostat")
    remote.proxy_arm(cfg, "modify", {"topic": topic, "setpoint": setpoint})
    _say(emit, f"armed: rewrite setpoint on {topic} to {setpoint:g}")
    mark = _mark(cfg, "thermostat")
    try:
        send(cfg, "phone", topic, "set", {"setpoint": requested}, emit)
        accepted = _wait_for(lambda: _events_since(cfg, "thermostat", mark, "accepted", topic))
        rejected = _rejection(cfg, "thermostat", mark)
    finally:
        remote.proxy_clear(cfg)
    if accepted:
        got = accepted[-1]["body"].get("setpoint")
        if got == setpoint:
            reason = f"phone asked for {requested:g}°C, thermostat accepted {got:g}°C"
            return AttackResult("modify", SUCCEEDED, reason, command)
    if rejected:
        return AttackResult("modify", BLOCKED, f"thermostat rejected: {rejected}", command)
    return AttackResult("modify", BLOCKED, "tampered command was not accepted", command)


def attack_replay(
    cfg: Config, emit: Emit, seq: int | None = None, topic: str | None = None
) -> AttackResult:
    """3. Broker replays a captured 'unlock front door'."""
    topic = topic or _cmd_topic(cfg, "front-door")
    target = cfg.device_for_topic(topic)
    if target is None:
        raise remote.RemoteError(f"no device listens on {topic}")
    command = _cmdline("attack", "replay", *(["--seq", str(seq)] if seq is not None else []))

    if seq is None:
        _say(emit, "waiting for the victim to unlock the door (simulated: phone sends unlock)")
        send(cfg, "phone", topic, "unlock", {}, emit)
        caps = _wait_for(lambda: remote.proxy_captures(cfg, topic=topic, limit=1))
        cap = caps[-1]
    else:
        caps = remote.proxy_captures(cfg, topic=topic, seq=seq, limit=1)
        if not caps:
            known = [c["seq"] for c in remote.proxy_captures(cfg, topic=topic, limit=20)]
            raise remote.RemoteError(f"no captured message with seq {seq} on {topic}: {known}")
        cap = caps[-1]
    _say(emit, f"captured #{cap['id']} on {topic} (seq={cap['seq']}, {cap['size']} bytes)")

    _say(emit, "victim locks the door again")
    send(cfg, "phone", topic, "lock", {}, emit)
    _wait_for(lambda: remote.device_state(cfg, target.id)["state"].get("locked"))

    mark = _mark(cfg, target.id)
    remote.proxy_inject(cfg, cap["id"])
    _say(emit, f"replayed capture #{cap['id']}")
    unlocked = _wait_for(lambda: not remote.device_state(cfg, target.id)["state"].get("locked"))
    rejected = _rejection(cfg, target.id, mark)
    details = {"capture": cap["id"], "seq": cap["seq"]}
    if unlocked:
        reason = f"{target.label} UNLOCKED again by replayed seq {cap['seq']}"
        return AttackResult("replay", SUCCEEDED, reason, command, details)
    why = f"{target.label} rejected: {rejected}" if rejected else "replay had no effect"
    return AttackResult("replay", BLOCKED, why, command, details)


def attack_redirect(cfg: Config, emit: Emit, from_topic: str, to_topic: str) -> AttackResult:
    """4. Broker moves 'unlock front door' onto the back door's topic."""
    command = _cmdline("attack", "redirect", "--from", from_topic, "--to", to_topic)
    victim = cfg.device_for_topic(to_topic)
    if victim is None:
        raise remote.RemoteError(f"no device listens on {to_topic}")

    if victim.kind == "lock":
        send(cfg, "phone", to_topic, "lock", {}, emit)
        _wait_for(lambda: remote.device_state(cfg, victim.id)["state"].get("locked"))

    remote.proxy_arm(cfg, "redirect", {"from_topic": from_topic, "to_topic": to_topic})
    _say(emit, f"armed: redirect {from_topic} -> {to_topic}")
    mark = _mark(cfg, victim.id)
    try:
        send(cfg, "phone", from_topic, "unlock", {}, emit)
        accepted = _wait_for(lambda: _events_since(cfg, victim.id, mark, "accepted", to_topic))
        rejected = _rejection(cfg, victim.id, mark)
    finally:
        remote.proxy_clear(cfg)
    if accepted:
        reason = f"{victim.label} accepted a command the phone sent to {from_topic}"
        return AttackResult("redirect", SUCCEEDED, reason, command)
    why = f"{victim.label} rejected: {rejected}" if rejected else "redirected command ignored"
    return AttackResult("redirect", BLOCKED, why, command)


def attack_drop(cfg: Config, emit: Emit, topic: str, wait: float = 4.0) -> AttackResult:
    """5. Broker silently drops messages on a topic (default: the smoke alarm)."""
    command = _cmdline("attack", "drop", "--topic", topic)
    source = cfg.device_for_topic(topic)
    if source is None:
        raise remote.RemoteError(f"no device publishes on {topic}")

    remote.proxy_arm(cfg, "drop", {"topic": topic})
    _say(emit, f"armed: silently drop everything on {topic}")
    phone_mark = _mark(cfg, "phone")
    source_mark = _mark(cfg, source.id)
    try:
        if source.kind == "smoke":
            send(cfg, "phone", source.topics["cmd"], "test", {}, emit)
        sent = _wait_for(lambda: _events_since(cfg, source.id, source_mark, "sent", topic))
        time.sleep(wait)
        received = _events_since(cfg, "phone", phone_mark, "accepted", topic)
    finally:
        remote.proxy_clear(cfg)

    if not sent:
        return AttackResult("drop", BLOCKED, f"{source.label} published nothing", command)
    if received:
        return AttackResult("drop", BLOCKED, "phone still received the message", command)
    reason = (
        f"{source.label} published on {topic}, phone never got it and nobody was alerted "
        f"(waited {wait:g}s)"
    )
    return AttackResult("drop", SUCCEEDED, reason, command)


# --- demo -------------------------------------------------------------------------------


def demo_reset(cfg: Config, emit: Emit) -> None:
    remote.proxy_reset(cfg)
    emit("[demo] evil broker: rules and captures cleared")
    for device in cfg.devices:
        remote.device_reset(cfg, device)
        emit(f"[demo] {device}: reset")
