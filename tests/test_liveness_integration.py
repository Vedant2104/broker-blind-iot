"""Phase 6 against the running stack: hub policy, liveness, quarantine.

attack 5 (drop alarm):        OFF → nobody notices      ON → hub DETECTS it
attack 7 (compromised device): OFF → reads door commands ON → quarantined + rekeyed
attack 8 (counterfeit device): OFF → unlocks the door    ON → blocked at every layer
"""

from __future__ import annotations

import os

import pytest

from cli import actions, remote
from securelib.config import load_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("BBIOT_INTEGRATION") != "1", reason="stack not running"),
]


def quiet(_line: str) -> None:
    pass


@pytest.fixture(scope="module")
def cfg():
    c = load_config()
    actions.set_keymode(c, "centralized", quiet)
    actions.demo_reset(c, quiet)
    yield c
    actions.set_security(c, "on", quiet)
    actions.release_all(c, quiet)


def test_no_legitimate_traffic_blocked_by_the_gateway(cfg) -> None:
    actions.set_security(cfg, "on", quiet)
    assert remote.hub_state(cfg)["quarantined"] == {}


def test_heartbeats_arrive(cfg) -> None:
    devices = ("front-door", "back-door", "thermostat", "smoke-kitchen", "phone")

    def all_fresh() -> bool:
        live = remote.hub_state(cfg)["liveness"]
        return all((live.get(d) or {}).get("heartbeat_age") is not None for d in devices)

    assert actions._wait_for(all_fresh, timeout=15), remote.hub_state(cfg)["liveness"]


def test_commands_are_acked_end_to_end(cfg) -> None:
    mark = remote.device_state(cfg, "phone")["last_event"]
    actions.send(cfg, "phone", "home/door/front/cmd", "lock", {}, quiet)
    acks = actions._wait_for(lambda: actions._events_since(cfg, "phone", mark, "ack"), timeout=5)
    assert acks and acks[0]["device"] == "front-door"


@pytest.mark.parametrize(("mode", "expected"), [("off", "SUCCEEDED"), ("on", "DETECTED")])
def test_drop_alarm(cfg, mode: str, expected: str) -> None:
    actions.set_security(cfg, mode, quiet)
    r = actions.attack_drop(cfg, quiet, "home/smoke/kitchen", wait=2)
    assert r.outcome == expected, r.reason


@pytest.mark.parametrize(("mode", "expected"), [("off", "SUCCEEDED"), ("on", "BLOCKED")])
def test_compromised_device(cfg, mode: str, expected: str) -> None:
    actions.set_security(cfg, mode, quiet)
    r = actions.attack_compromised_device(cfg, quiet, "thermostat")
    assert r.outcome == expected, r.reason
    if mode == "on":
        assert "quarantined" in r.reason and "only holds epoch" in r.reason


@pytest.mark.parametrize(("mode", "expected"), [("off", "SUCCEEDED"), ("on", "BLOCKED")])
def test_counterfeit(cfg, mode: str, expected: str) -> None:
    actions.set_security(cfg, mode, quiet)
    r = actions.attack_counterfeit(cfg, quiet)
    assert r.outcome == expected, r.reason


def test_quarantines_are_released_afterwards(cfg) -> None:
    actions.set_security(cfg, "on", quiet)
    assert remote.hub_state(cfg)["quarantined"] == {}
