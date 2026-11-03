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
    door = build(cfg, "front-door")
    assert door.state()["locked"] is True
    _deliver(door, "home/door/front/cmd", {"cmd": "unlock"})
    assert door.state() == {"locked": False, "by": "phone"}
    _deliver(door, "home/door/front/cmd", {"cmd": "lock"})
    assert door.state()["locked"] is True


def test_lock_ignores_unknown_command(cfg: Config) -> None:
    door = build(cfg, "front-door")
    _deliver(door, "home/door/front/cmd", {"cmd": "explode"})
    assert door.state()["locked"] is True


def test_malformed_payload_is_rejected_and_logged(cfg: Config) -> None:
    door = build(cfg, "front-door")
    door._on_message(None, None, type("M", (), {"topic": "t", "payload": b"\x00garbage"})())
    ev = door.events.after(0)[-1]
    assert ev["kind"] == "rejected" and "malformed" in ev["reason"]
    assert door.state()["locked"] is True


def test_thermostat_set(cfg: Config) -> None:
    t = build(cfg, "thermostat")
    _deliver(t, "home/thermostat/living/cmd", {"cmd": "set", "setpoint": 23.5})
    assert t.state()["setpoint"] == 23.5
    _deliver(t, "home/thermostat/living/cmd", {"cmd": "set", "setpoint": "hot"})
    assert t.state()["setpoint"] == 23.5


def test_smoke_test_raises_alarm_on_alarm_topic(cfg: Config) -> None:
    s = build(cfg, "smoke-kitchen")
    _deliver(s, "home/smoke/kitchen/cmd", {"cmd": "test"})
    assert s.state()["alarm"] is True
    sent = [e for e in s.events.after(0) if e["kind"] == "sent"]
    assert any(e["topic"] == "home/smoke/kitchen" for e in sent)


def test_phone_counts_alarms_not_state_updates(cfg: Config) -> None:
    phone = build(cfg, "phone")
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
