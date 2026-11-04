"""Device behaviour without MQTT: handlers, state, send validation."""

from __future__ import annotations

import pytest

from devices.base import SendError, validate_send
from devices.kinds import build
from securelib.config import Config


def _deliver(device, topic: str, body: dict, sender: str = "phone") -> None:
    payload = device.channel.__class__(sender).seal(topic, body)
    device._on_message(None, None, type("M", (), {"topic": topic, "payload": payload})())


def test_lock_unlock_and_lock(cfg: Config) -> None:
    door = build(cfg, "front-door", mode="off")
    assert door.state()["locked"] is True
    _deliver(door, "home/door/front/cmd", {"cmd": "unlock"})
    assert door.state() == {"locked": False, "by": "phone"}
    _deliver(door, "home/door/front/cmd", {"cmd": "lock"})
    assert door.state()["locked"] is True


def test_lock_ignores_unknown_command(cfg: Config) -> None:
    door = build(cfg, "front-door", mode="off")
    _deliver(door, "home/door/front/cmd", {"cmd": "explode"})
    assert door.state()["locked"] is True


def test_malformed_payload_is_rejected_and_logged(cfg: Config) -> None:
    door = build(cfg, "front-door", mode="off")
    door._on_message(None, None, type("M", (), {"topic": "t", "payload": b"\x00garbage"})())
    ev = door.events.after(0)[-1]
    assert ev["kind"] == "rejected" and "malformed" in ev["reason"]
    assert door.state()["locked"] is True


def test_thermostat_set(cfg: Config) -> None:
    t = build(cfg, "thermostat", mode="off")
    _deliver(t, "home/thermostat/living/cmd", {"cmd": "set", "setpoint": 23.5})
    assert t.state()["setpoint"] == 23.5
    _deliver(t, "home/thermostat/living/cmd", {"cmd": "set", "setpoint": "hot"})
    assert t.state()["setpoint"] == 23.5


def test_smoke_test_raises_alarm_on_alarm_topic(cfg: Config) -> None:
    s = build(cfg, "smoke-kitchen", mode="off")
    _deliver(s, "home/smoke/kitchen/cmd", {"cmd": "test"})
    assert s.state()["alarm"] is True
    sent = [e for e in s.events.after(0) if e["kind"] == "sent"]
    assert any(e["topic"] == "home/smoke/kitchen" for e in sent)


def test_phone_counts_alarms_not_state_updates(cfg: Config) -> None:
    phone = build(cfg, "phone", mode="off")
    _deliver(phone, "home/smoke/kitchen/state", {"alarm": False}, sender="smoke-kitchen")
    assert phone.state()["alarms_received"] == 0
    _deliver(phone, "home/smoke/kitchen", {"alarm": "smoke"}, sender="smoke-kitchen")
    assert phone.state()["alarms_received"] == 1


def test_phone_subscribes_to_states_and_alarms_only(cfg: Config) -> None:
    subs = build(cfg, "phone").subscriptions()
    assert "home/smoke/kitchen" in subs
    assert not any(t.endswith("/cmd") for t in subs)


def test_validate_send_accepts_known_commands(cfg: Config) -> None:
    assert validate_send(cfg, "home/door/front/cmd", "unlock", {}) == {"cmd": "unlock"}
    body = validate_send(cfg, "home/thermostat/living/cmd", "set", {"setpoint": "22"})
    assert body == {"cmd": "set", "setpoint": 22.0}


@pytest.mark.parametrize(
    ("topic", "cmd", "args", "msg"),
    [
        ("home/../../etc", "unlock", {}, "unknown topic"),
        ("home/door/front/state", "unlock", {}, "not a command topic"),
        ("home/door/front/cmd", "rm -rf", {}, "unknown command"),
        ("home/thermostat/living/cmd", "set", {}, "numeric setpoint"),
        ("home/thermostat/living/cmd", "set", {"setpoint": 90}, "between"),
    ],
)
def test_validate_send_rejects(cfg: Config, topic, cmd, args, msg) -> None:
    with pytest.raises(SendError, match=msg):
        validate_send(cfg, topic, cmd, args)


class _StaticGroup:
    """One fixed group key (epoch 1), enough to seal test messages."""

    mode = "centralized"

    def current(self):
        return 1, bytes(32)

    def key_for(self, epoch: int):
        return bytes(32) if epoch == 1 else None

    def subscriptions(self):
        return []

    def handle(self, topic, payload) -> None:
        pass

    def tick(self) -> None:
        pass

    def status(self):
        return {"mode": self.mode, "epoch": 1}


def _hub_and_sealer(cfg: Config, sender: str):
    from securelib.channel import Channel

    hub = build(cfg, "hub", mode="on")
    group = _StaticGroup()
    hub.channel.groups["centralized"] = group
    return hub, Channel(sender, mode="on", group=group)


def test_own_echo_is_ignored_not_rejected(cfg: Config) -> None:
    """MQTT echoes our own publishes (the hub's alarm ack on ack/+): no
    'unknown sender' rejection for ourselves."""
    hub, sealer = _hub_and_sealer(cfg, "hub")
    mark = hub.events.last_id
    payload = sealer.seal("ack/hub", {"ack": "alarm"})
    assert hub.own_echo(payload)
    hub._on_message(None, None, type("M", (), {"topic": "ack/hub", "payload": payload})())
    assert hub.events.after(mark) == []


def test_other_unknown_sender_still_rejected(cfg: Config) -> None:
    hub, sealer = _hub_and_sealer(cfg, "intruder")
    payload = sealer.seal("ack/hub", {"ack": "alarm"})
    assert not hub.own_echo(payload)
    hub._on_message(None, None, type("M", (), {"topic": "ack/hub", "payload": payload})())
    last = hub.events.after(0)[-1]
    assert last["kind"] == "rejected"  # still verified (and refused), not skipped


def test_handler_error_does_not_kill_the_mqtt_thread(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing handler (e.g. the directory timing out) must not escape to paho:
    that would silently stop the device from receiving anything."""
    door = build(cfg, "front-door", mode="off")

    def boom(*_a):
        raise RuntimeError("directory unreachable: read timed out")

    monkeypatch.setattr(door, "_on_message", boom)
    msg = type("M", (), {"topic": "home/door/front/cmd", "payload": b"{}"})()
    door._on_mqtt_message(None, None, msg)  # does not raise
    ev = door.events.after(0)[-1]
    assert ev["kind"] == "rejected" and ev["reason"] == "internal error"
