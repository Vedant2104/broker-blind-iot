"""Phase 1 baseline: with security OFF, attacks 1-5 succeed against the running
stack. Run with `make test-integration` (needs `docker compose up -d`)."""

from __future__ import annotations

import os

import pytest

from cli import actions
from securelib.config import load_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("BBIOT_INTEGRATION") != "1", reason="stack not running"),
]

FRONT, BACK = "home/door/front/cmd", "home/door/back/cmd"


@pytest.fixture(scope="module")
def cfg():
    c = load_config()
    actions.demo_reset(c, lambda _line: None)
    return c


def _quiet(_line: str) -> None:
    pass


def test_attack_read_succeeds(cfg) -> None:
    assert actions.attack_read(cfg, _quiet).outcome == "SUCCEEDED"


def test_attack_modify_succeeds(cfg) -> None:
    r = actions.attack_modify(cfg, _quiet, setpoint=30, requested=21)
    assert r.outcome == "SUCCEEDED", r.reason


def test_attack_replay_succeeds(cfg) -> None:
    r = actions.attack_replay(cfg, _quiet)
    assert r.outcome == "SUCCEEDED", r.reason


def test_attack_redirect_succeeds(cfg) -> None:
    r = actions.attack_redirect(cfg, _quiet, FRONT, BACK)
    assert r.outcome == "SUCCEEDED", r.reason


def test_attack_drop_succeeds(cfg) -> None:
    r = actions.attack_drop(cfg, _quiet, "home/smoke/kitchen", wait=2)
    assert r.outcome == "SUCCEEDED", r.reason


def test_rules_are_disarmed_after_attacks(cfg) -> None:
    from cli import remote

    assert remote.proxy_status(cfg)["rules"] == {"drop": [], "redirect": {}, "modify": {}}
