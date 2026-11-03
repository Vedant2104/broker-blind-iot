"""Hub building blocks: MUD policy matching, quarantine notices, liveness monitor."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hub.monitor import Monitor
from hub.policy import DENY_ALL, PolicyStore, Profile, filter_covers, topic_matches, write_profiles
from hub.quarantine import NoticeTracker, sign_notice, verify_notice
from securelib.config import Config
from securelib.pki import TrustError

# --- topic matching --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flt", "topic", "ok"),
    [
        ("home/door/front/cmd", "home/door/front/cmd", True),
        ("home/+/front/cmd", "home/door/front/cmd", True),
        ("home/#", "home/door/front/cmd", True),
        ("home/+", "home/door/front", False),
        ("home/door/front/cmd", "home/door/back/cmd", False),
        ("hb/+", "hb/thermostat", True),
    ],
)
def test_topic_matches(flt: str, topic: str, ok: bool) -> None:
    assert topic_matches(flt, topic) is ok


@pytest.mark.parametrize(
    ("allowed", "requested", "ok"),
    [
        ("home/thermostat/living/cmd", "home/thermostat/living/cmd", True),
        ("ack/+", "ack/front-door", True),
        ("home/#", "home/door/+/cmd", True),
        # a device must not widen what it may see with its own wildcards:
        ("home/thermostat/living/cmd", "home/+/living/cmd", False),
        ("home/thermostat/living/cmd", "home/#", False),
        ("ack/+", "ack/#", False),
        ("ack/+", "#", False),
        ("ack/+", "ack/front-door/x", False),
    ],
)
def test_filter_covers(allowed: str, requested: str, ok: bool) -> None:
    assert filter_covers(allowed, requested) is ok


# --- profiles -------------------------------------------------------------------------------


@pytest.fixture
def store(cfg: Config, tmp_path) -> PolicyStore:
    write_profiles(cfg, tmp_path / "mud")
    return PolicyStore(tmp_path / "mud")


def test_thermostat_profile(store: PolicyStore) -> None:
    p = store.get("thermostat")
    assert p.check_publish("home/thermostat/living/state") is None
    assert p.check_subscribe("home/thermostat/living/cmd") is None
    # attack 7: a compromised thermostat wants the door commands
    assert "not in thermostat's MUD profile" in p.check_subscribe("home/door/front/cmd")
    assert p.check_subscribe("home/#") is not None
    assert p.check_publish("home/door/front/cmd") is not None
    assert p.accepts_command_from("phone") and not p.accepts_command_from("thermostat")


def test_phone_may_command_but_not_impersonate(store: PolicyStore) -> None:
    p = store.get("phone")
    assert p.check_publish("home/door/front/cmd") is None
    assert p.check_publish("home/door/front/state") is not None
    assert p.check_publish("hb/front-door") is not None


def test_unknown_identity_may_do_nothing(store: PolicyStore) -> None:
    assert store.get("counterfeit") is DENY_ALL
    assert store.get("counterfeit").check_publish("home/door/front/cmd") is not None
    assert store.get("dashboard").check_subscribe("home/#") is not None


def test_committed_profiles_match_generator(cfg: Config, tmp_path) -> None:
    """config/mud/*.json must be regenerated when home.yaml changes."""
    from tests.conftest import REPO

    write_profiles(cfg, tmp_path / "gen")
    committed = PolicyStore(REPO / "config" / "mud")
    generated = PolicyStore(tmp_path / "gen")
    assert {k: p.data for k, p in committed.profiles.items()} == {
        k: p.data for k, p in generated.profiles.items()
    }


def test_profile_from_dict() -> None:
    p = Profile({"device": "x", "publish": ["a/+"], "subscribe": []})
    assert p.check_publish("a/b") is None


# --- quarantine notices ---------------------------------------------------------------------

HUB = Ed25519PrivateKey.generate()


def test_notice_roundtrip_and_versioning() -> None:
    t = NoticeTracker()
    assert t.offer(sign_notice(HUB, 1, {"thermostat": "policy"}), HUB.public_key())
    assert t.quarantined == {"thermostat": "policy"}
    # a replayed OLDER list (e.g. one that didn't quarantine thermostat) is ignored
    assert not t.offer(sign_notice(HUB, 0, {}), HUB.public_key())
    assert t.quarantined == {"thermostat": "policy"}
    assert t.offer(sign_notice(HUB, 2, {}), HUB.public_key())
    assert t.quarantined == {}


def test_forged_notice_rejected() -> None:
    forged = sign_notice(Ed25519PrivateKey.generate(), 9, {"phone": "x"})
    with pytest.raises(TrustError):
        verify_notice(forged, HUB.public_key())
    tampered = sign_notice(HUB, 9, {"phone": "x"})
    tampered["notice"]["quarantined"] = {}
    with pytest.raises(TrustError):
        verify_notice(tampered, HUB.public_key())


# --- liveness monitor -----------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def monitor(clock: Clock) -> Monitor:
    return Monitor(heartbeat_interval=5, grace=2, now=clock, wall_ms=lambda: int(clock.t * 1000))


def test_gap_reported_after_grace() -> None:
    c = Clock()
    m = monitor(c)
    m.on_message("smoke", 10, 100_000)
    m.on_message("smoke", 12, 100_500)  # 11 missing
    assert m.tick() == []  # within grace: may still arrive
    c.t += 3
    alerts = m.tick()
    assert len(alerts) == 1 and "DROPPED: 1 message(s) from smoke" in alerts[0]["title"]
    assert alerts[0]["seq"] == "11"
    assert m.tick() == []  # reported once


def test_late_arrival_is_not_a_drop() -> None:
    c = Clock()
    m = monitor(c)
    m.on_message("smoke", 10, 0)
    m.on_message("smoke", 12, 0)
    m.on_message("smoke", 11, 0)  # reordered
    c.t += 5
    assert m.tick() == []


def test_restart_jump_is_not_a_drop() -> None:
    c = Clock()
    m = monitor(c)
    m.on_message("lock", 20, 0)
    alerts = m.on_message("lock", 1001, 0)
    c.t += 5
    assert "restarted" in alerts[0]["title"] and m.tick() == []


def test_missing_heartbeat_and_recovery() -> None:
    c = Clock()
    m = monitor(c)
    m.expect_heartbeats = {"front-door"}
    m.on_heartbeat("front-door", {})
    c.t += 10
    assert m.tick() == []
    c.t += 6
    alerts = m.tick()
    assert alerts and alerts[0]["title"].startswith("MISSING HEARTBEAT")
    assert m.tick() == []  # once
    assert "back" in m.on_heartbeat("front-door", {})[0]["title"]


def test_unacked_alarm_in_heartbeat() -> None:
    c = Clock()
    m = monitor(c)
    body = {"unacked_alarms": [{"seq": 77, "ts_ms": int((c.t - 6) * 1000)}]}
    alerts = m.on_heartbeat("smoke-kitchen", body)
    assert alerts[0]["title"].startswith("ALARM DROPPED") and alerts[0]["detect_s"] == 6.0
    assert m.on_heartbeat("smoke-kitchen", body) == []  # reported once


# --- gateway decisions (no sockets) ---------------------------------------------------------


class FakeWriter:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


def gateway(cfg: Config, store: PolicyStore, enforcing: bool = True):
    from hub.gateway import PolicyGateway

    violations: list[tuple[str, str]] = []
    gw = PolicyGateway(
        cfg,
        store,
        enforcing=lambda: enforcing,
        is_quarantined=lambda _i: False,
        on_violation=lambda ident, why: violations.append((ident, why)),
        upstream=("x", 1),
    )
    return gw, violations


def test_gateway_blocks_subscription_outside_profile(cfg: Config, store: PolicyStore) -> None:
    from evilbroker.wire import Subscribe, encode_subscribe

    gw, violations = gateway(cfg, store)
    w = FakeWriter()
    raw = encode_subscribe(Subscribe(5, [("home/door/front/cmd", 1)]), False)
    assert gw._check("thermostat", raw, {"v5": False}, w) is None  # not forwarded
    assert w.closed and w.sent[0] == b"\x90\x03\x00\x05\x80"  # SUBACK failure
    assert violations[0][0] == "thermostat" and "home/door/front/cmd" in violations[0][1]


def test_gateway_forwards_allowed_traffic(cfg: Config, store: PolicyStore) -> None:
    from evilbroker.wire import Publish, Subscribe, encode_publish, encode_subscribe

    gw, violations = gateway(cfg, store)
    sub = encode_subscribe(Subscribe(5, [("home/thermostat/living/cmd", 1)]), False)
    pub = encode_publish(Publish("home/thermostat/living/state", b"x", qos=1, packet_id=3), False)
    assert gw._check("thermostat", sub, {"v5": False}, FakeWriter()) == sub
    assert gw._check("thermostat", pub, {"v5": False}, FakeWriter()) == pub
    assert violations == []


def test_gateway_blocks_publish_and_acks_sender(cfg: Config, store: PolicyStore) -> None:
    from evilbroker.wire import Publish, encode_publish

    gw, violations = gateway(cfg, store)
    w = FakeWriter()
    raw = encode_publish(Publish("home/door/front/cmd", b"x", qos=1, packet_id=7), False)
    assert gw._check("counterfeit", raw, {"v5": False}, w) is None
    assert w.sent == [b"\x40\x02\x00\x07"] and violations[0][0] == "counterfeit"


def test_gateway_passes_everything_with_security_off(cfg: Config, store: PolicyStore) -> None:
    from evilbroker.wire import Subscribe, encode_subscribe

    gw, violations = gateway(cfg, store, enforcing=False)
    raw = encode_subscribe(Subscribe(5, [("home/#", 0)]), False)
    assert gw._check("thermostat", raw, {"v5": False}, FakeWriter()) == raw and not violations
