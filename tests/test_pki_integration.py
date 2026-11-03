"""Phase 2 against the running stack: every commissioned device holds a
root-signed, logged certificate for its own keys, and the log verifies."""

from __future__ import annotations

import os

import pytest

from cli import pki_actions, remote
from securelib.config import load_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("BBIOT_INTEGRATION") != "1", reason="stack not running"),
]


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def test_log_verifies(cfg) -> None:
    lines: list[str] = []
    assert pki_actions.log_verify(cfg, lines.append), "\n".join(lines)


def test_commissioned_devices_are_trusted(cfg) -> None:
    for dev in cfg.devices.values():
        if not dev.commissioned:
            continue
        ident = remote.device_identity(cfg, dev.id)
        assert ident["cert"]["status"] == "trusted", (dev.id, ident["cert"])


def test_directory_serves_each_device_its_own_keys(cfg) -> None:
    served = {e["device_id"]: e["fingerprint"] for e in pki_actions.directory(cfg).list_certs()}
    for dev in cfg.devices.values():
        if dev.commissioned:
            assert served[dev.id] == remote.device_identity(cfg, dev.id)["fingerprint"]


def test_single_admin_cannot_get_a_cert_issued(cfg) -> None:
    from securelib.pki import TrustError

    aid = pki_actions.pair(cfg, "garage-lock", lambda _l: None)
    pki_actions.approve(cfg, "B", aid, lambda _l: None, auto_issue=False)
    with pytest.raises(TrustError, match="needs 2 admin approvals"):
        pki_actions.issue(cfg, aid, lambda _l: None)
