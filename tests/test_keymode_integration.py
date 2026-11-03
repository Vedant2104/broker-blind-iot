"""Phase 5 against the running stack: centralized (KDC) vs decentralized (MLS).

attack 9 (directory swaps a key):   OFF → a naive client is fooled
                                    ON  → caught (cert: root check; MLS: key-package check)
attack 10 (KDC + directory leak):   centralized → KDC key decrypts traffic
                                    decentralized → nothing decrypts
"""

from __future__ import annotations

import os
import time

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
    actions.set_security(c, "on", quiet)
    yield c
    actions.set_security(c, "on", quiet)
    actions.set_keymode(c, "centralized", quiet)


def _mls_epochs(cfg) -> dict[str, int | None]:
    return {
        d: (remote.device_state(cfg, d).get("groups") or {}).get("decentralized", {}).get("epoch")
        for d in cfg.devices
    }


def _wait(pred, timeout: float = 75.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(1)
    return None


def test_all_devices_share_one_mls_epoch(cfg) -> None:
    assert _wait(
        lambda: (
            len(set(_mls_epochs(cfg).values()) - {None}) == 1
            and None not in _mls_epochs(cfg).values()
        )
    ), _mls_epochs(cfg)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("read", "ciphertext"),
        ("modify", "tag invalid"),
        ("replay", "replay"),
        ("redirect", "wrong topic"),
    ],
)
def test_decentralized_blocks_broker_attacks(cfg, name: str, reason: str) -> None:
    actions.set_keymode(cfg, "decentralized", quiet)
    fn = {
        "read": lambda: actions.attack_read(cfg, quiet),
        "modify": lambda: actions.attack_modify(cfg, quiet),
        "replay": lambda: actions.attack_replay(cfg, quiet),
        "redirect": lambda: actions.attack_redirect(
            cfg, quiet, "home/door/front/cmd", "home/door/back/cmd"
        ),
    }[name]
    r = fn()
    assert r.outcome == "BLOCKED" and reason in r.reason, r.reason


def test_decentralized_swap_key_caught_by_key_package_check(cfg) -> None:
    actions.set_keymode(cfg, "decentralized", quiet)
    r = actions.attack_swap_key(cfg, quiet, "thermostat")
    assert r.outcome == "BLOCKED" and "NOT its certified key" in r.reason, r.reason


def test_victim_heals_back_into_the_mls_group(cfg) -> None:
    assert _wait(
        lambda: (
            _mls_epochs(cfg).get("thermostat") is not None
            and len(set(_mls_epochs(cfg).values())) == 1
        )
    ), _mls_epochs(cfg)


def test_decentralized_compromised_kdc_and_directory_read_nothing(cfg) -> None:
    actions.set_keymode(cfg, "decentralized", quiet)
    r = actions.attack_kdc_vs_directory(cfg, quiet)
    assert r.outcome == "BLOCKED", r.reason


def test_centralized_compromised_kdc_reads_everything(cfg) -> None:
    actions.set_keymode(cfg, "centralized", quiet)
    r = actions.attack_kdc_vs_directory(cfg, quiet)
    assert r.outcome == "SUCCEEDED" and "KDC" in r.reason, r.reason


def test_centralized_swap_key_caught_by_root_check(cfg) -> None:
    actions.set_keymode(cfg, "centralized", quiet)
    r = actions.attack_swap_key(cfg, quiet, "thermostat")
    assert r.outcome == "BLOCKED" and "does not verify against the root" in r.reason, r.reason


def test_security_off_naive_client_is_fooled(cfg) -> None:
    actions.set_security(cfg, "off", quiet)
    try:
        r = actions.attack_swap_key(cfg, quiet, "thermostat")
        assert r.outcome == "SUCCEEDED", r.reason
    finally:
        actions.set_security(cfg, "on", quiet)
