"""Attacks against the running stack, security OFF vs ON.

OFF (TLS only): attacks 1-5 succeed, attack 6 (unsigned DH) steals the key.
ON (broker-blind): attacks 1-4 and 6 are blocked; 5 (drop) is detected by the hub.
Run with `make test-integration` (needs `docker compose up -d`)."""

from __future__ import annotations

import os
import time

import pytest

from cli import actions, pki_actions, remote
from securelib.config import load_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("BBIOT_INTEGRATION") != "1", reason="stack not running"),
]

FRONT, BACK, SMOKE = "home/door/front/cmd", "home/door/back/cmd", "home/smoke/kitchen"


def quiet(_line: str) -> None:
    pass


@pytest.fixture(scope="module")
def cfg():
    c = load_config()
    actions.set_keymode(c, "centralized", quiet)  # these tests exercise the KDC mode
    actions.demo_reset(c, quiet)
    yield c
    actions.set_security(c, "on", quiet)


def run_attack(cfg, name: str):
    return {
        "read": lambda: actions.attack_read(cfg, quiet),
        "modify": lambda: actions.attack_modify(cfg, quiet, setpoint=30, requested=21),
        "replay": lambda: actions.attack_replay(cfg, quiet),
        "redirect": lambda: actions.attack_redirect(cfg, quiet, FRONT, BACK),
        "drop": lambda: actions.attack_drop(cfg, quiet, SMOKE, wait=2),
    }[name]()


@pytest.mark.parametrize("name", ["read", "modify", "replay", "redirect", "drop"])
def test_security_off_attacks_succeed(cfg, name: str) -> None:
    actions.set_security(cfg, "off", quiet)
    r = run_attack(cfg, name)
    assert r.outcome == "SUCCEEDED", r.reason


@pytest.mark.parametrize(
    ("name", "expected", "reason"),
    [
        ("read", "BLOCKED", "ciphertext"),
        ("modify", "BLOCKED", "tag invalid"),
        ("replay", "BLOCKED", "replay"),
        ("redirect", "BLOCKED", "wrong topic"),
        ("drop", "DETECTED", "hub detected"),  # can't be prevented, but is noticed
    ],
)
def test_security_on_attacks(cfg, name: str, expected: str, reason: str) -> None:
    actions.set_security(cfg, "on", quiet)
    time.sleep(1)
    r = run_attack(cfg, name)
    assert r.outcome == expected, r.reason
    assert reason in r.reason


def test_unsigned_key_exchange_is_broken(cfg) -> None:
    actions.set_security(cfg, "on", quiet)
    r = actions.attack_mitm_dh(cfg, quiet, unsigned=True)
    assert r.outcome == "SUCCEEDED", r.reason
    assert "stole" in r.reason


def test_signed_key_exchange_detects_mitm(cfg) -> None:
    r = actions.attack_mitm_dh(cfg, quiet, unsigned=False)
    assert r.outcome == "BLOCKED", r.reason
    assert "signature invalid" in r.reason


def test_rules_are_disarmed_after_attacks(cfg) -> None:
    rules = remote.proxy_status(cfg)["rules"]
    assert rules == {"drop": [], "redirect": {}, "modify": {}, "mitm_dh": []}


def _epoch(cfg, device: str) -> int | None:
    return remote.device_state(cfg, device)["group"]["epoch"]


def _wait(pred, timeout: float = 15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.5)
    return None


def test_revoked_device_cannot_read_new_traffic(cfg) -> None:
    """Revoke garage-lock (2 of 3), KDC rekeys; garage-lock stays on the old epoch
    and rejects new messages. Then re-pair it to restore the home."""
    actions.set_security(cfg, "on", quiet)
    assert _wait(lambda: _epoch(cfg, "garage-lock")), "garage-lock has no group key"
    old = _epoch(cfg, "garage-lock")

    aid = pki_actions.revoke(cfg, "garage-lock", quiet)
    pki_actions.approve(cfg, "B", aid, quiet, auto_issue=False)
    pki_actions.approve(cfg, "C", aid, quiet)
    assert _wait(lambda: "garage-lock" not in remote.kdc_status(cfg)["members"])
    assert _wait(lambda: (_epoch(cfg, "phone") or 0) > old)
    assert _epoch(cfg, "garage-lock") == old

    mark = remote.device_state(cfg, "garage-lock")["last_event"]
    actions.send(cfg, "phone", "home/door/garage/cmd", "unlock", {}, quiet)
    rejected = _wait(
        lambda: [
            e
            for e in remote.device_events(cfg, "garage-lock", after=mark)
            if e["kind"] == "rejected"
        ]
    )
    assert rejected and rejected[-1]["reason"].startswith("wrong epoch")
    assert remote.device_state(cfg, "garage-lock")["state"]["locked"] is True

    # restore: re-commission with a new certificate; it rejoins under the new epoch
    aid = pki_actions.pair(cfg, "garage-lock", quiet)
    pki_actions.approve(cfg, "A", aid, quiet, auto_issue=False)
    pki_actions.approve(cfg, "C", aid, quiet)
    assert _wait(lambda: "garage-lock" in remote.kdc_status(cfg)["members"], timeout=60)
    assert _wait(
        lambda: remote.device_identity(cfg, "garage-lock")["cert"]["status"] == "trusted",
        timeout=60,
    )
