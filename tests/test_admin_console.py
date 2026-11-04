"""Admin console: only the dashboard/cli may ask it to sign, with validated input."""

from __future__ import annotations

import dataclasses
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from cli import pki_actions
from rootca import console
from securelib.config import Config
from securelib.tls import client_paths, init_tls


@pytest.fixture
def cfg(cfg: Config, tmp_path: Path) -> Config:
    return dataclasses.replace(cfg, offline_dir=tmp_path / "offline")


@pytest.fixture
def server(cfg: Config) -> Iterator[int]:
    init_tls(cfg.tls_dir, cfg.identities)
    srv = console.make_server(cfg, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _client(cfg: Config, identity: str | None) -> ssl.SSLContext:
    ca = client_paths(cfg.tls_dir, "dashboard").ca
    ctx = ssl.create_default_context(cafile=str(ca))
    if identity:
        paths = client_paths(cfg.tls_dir, identity)
        ctx.load_cert_chain(paths.cert, paths.key)
    return ctx


def test_dashboard_may_call(cfg: Config, server: int) -> None:
    r = httpx.get(f"https://127.0.0.1:{server}/status", verify=_client(cfg, "dashboard"))
    assert r.status_code == 200
    assert r.json() == {"admins": [], "root": False}  # no offline keys in this test


@pytest.mark.parametrize("identity", ["thermostat", "evil-proxy", "counterfeit", "kdc"])
def test_other_identities_refused(cfg: Config, server: int, identity: str) -> None:
    """A compromised device (valid transport cert) cannot get approvals signed."""
    r = httpx.post(
        f"https://127.0.0.1:{server}/approve",
        json={"admin": "A", "action": "0123456789ab"},
        verify=_client(cfg, identity),
    )
    assert r.status_code == 403


def test_no_client_cert_refused(cfg: Config, server: int) -> None:
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"https://127.0.0.1:{server}/status", verify=_client(cfg, None))


@pytest.mark.parametrize(
    ("admin", "action"),
    [("D", "0123456789ab"), ("A", "../../etc"), ("A", "0123456789AB"), ("A", "abc")],
)
def test_bad_input_rejected_before_signing(
    cfg: Config, admin: str, action: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pki_actions, "approve", lambda *a, **k: pytest.fail("must not sign"))
    with pytest.raises(console.ConsoleError):
        console.approve(cfg, admin, action)


def test_approve_runs_shared_code(cfg: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake(cfg_, admin, action_id, emit, *, identity):
        calls.append((admin, action_id, identity))
        emit(f"[admin {admin}] ✓ signed — approvals 1/2 (A)")
        return {"id": action_id, "approvals": {"A": "sig"}, "status": "pending"}

    monkeypatch.setattr(pki_actions, "approve", fake)
    out = console.approve(cfg, "A", "0123456789ab")
    assert calls == [("A", "0123456789ab", "admin-console")]
    assert out == {"lines": ["[admin A] ✓ signed — approvals 1/2 (A)"], "issued": False}


def test_caller_name() -> None:
    cert = {"subject": ((("organizationName", "bbiot"),), (("commonName", "dashboard"),))}
    assert console.caller_name(cert) == "dashboard"
    assert console.caller_name(None) is None
