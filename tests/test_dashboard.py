"""Dashboard backend: only allowlisted actions with validated params can run."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cli import actions
from dashboard import app as dash
from securelib.config import Config


@pytest.fixture
def client(cfg: Config) -> TestClient:
    return TestClient(dash.create_app(cfg, start_background=False))


def test_snapshot(client: TestClient) -> None:
    snap = client.get("/api/snapshot").json()
    assert snap["type"] == "snapshot"
    assert snap["security"] == "unknown"  # no devices reachable in this test


def test_unknown_action_404(client: TestClient) -> None:
    assert client.post("/api/actions/shell.exec", json={"cmd": "id"}).status_code == 404


@pytest.mark.parametrize("setpoint", [99, 0, "hot"])
def test_bad_params_422(client: TestClient, setpoint) -> None:
    r = client.post("/api/actions/phone.set_thermostat", json={"setpoint": setpoint})
    assert r.status_code == 422


def test_allowlist_is_fixed() -> None:
    groups = {"phone", "attack", "demo", "log", "security", "keymode", "pair", "admin"}
    assert all(name.split(".")[0] in groups for name in dash.ACTIONS)


def test_action_runs_shared_code_and_reports_command(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def fake_redirect(cfg, emit, from_topic, to_topic):
        calls.append((from_topic, to_topic))
        emit("[attacker] armed")
        return actions.AttackResult("redirect", "SUCCEEDED", "back door opened", "x")

    monkeypatch.setattr(actions, "attack_redirect", fake_redirect)
    r = client.post("/api/actions/attack.redirect")
    assert r.status_code == 200
    data = r.json()
    assert data["command"] == (
        "bbiot attack redirect --from home/door/front/cmd --to home/door/back/cmd"
    )
    assert data["result"]["outcome"] == "SUCCEEDED"
    assert calls == [("home/door/front/cmd", "home/door/back/cmd")]
    assert client.get("/api/snapshot").json()["alerts"][-1]["severity"] == "critical"


def test_websocket_sends_snapshot_first(client: TestClient) -> None:
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "snapshot"


def test_console_history_in_snapshot(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(actions, "attack_read", lambda cfg, emit: emit("[attacker] hi") or None)
    client.post("/api/actions/attack.read")
    lines = [c["line"] for c in client.get("/api/snapshot").json()["console"]]
    assert lines == ["$ bbiot attack read", "[attacker] hi"]


def test_pair_only_known_devices(client: TestClient) -> None:
    assert client.post("/api/actions/pair.start", json={"device": "toaster"}).status_code == 422
    r = client.post("/api/actions/pair.start", json={"device": "garage-lock; rm -rf /"})
    assert r.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"admin": "D", "action": "0123456789ab"},
        {"admin": "A", "action": "0123456789abcd"},
        {"admin": "A", "action": "$(id)"},
        {"admin": "A"},
    ],
)
def test_approve_params_validated(client: TestClient, body: dict) -> None:
    assert client.post("/api/actions/admin.approve", json=body).status_code == 422


def test_approve_goes_through_admin_console(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dashboard holds no admin keys: approvals are signed by the admin console."""
    calls = []

    class FakeConsole:
        def __init__(self, cfg, identity):
            calls.append(identity)

        def approve(self, admin, action):
            calls.append((admin, action))
            return {"lines": [f"[admin {admin}] ✓ signed — approvals 2/2 (A, B)"], "issued": True}

    monkeypatch.setattr(dash, "ConsoleClient", FakeConsole)
    r = client.post("/api/actions/admin.approve", json={"admin": "B", "action": "0123456789ab"})
    assert r.status_code == 200
    assert r.json()["command"] == "bbiot admin approve --admin B --action 0123456789ab"
    assert r.json()["data"]["issued"] is True
    assert calls == ["dashboard", ("B", "0123456789ab")]


def test_console_unreachable_is_reported(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Down:
        def __init__(self, cfg, identity):
            pass

        def approve(self, admin, action):
            raise dash.ServiceError("admin console unreachable (offline?)")

    monkeypatch.setattr(dash, "ConsoleClient", Down)
    r = client.post("/api/actions/admin.approve", json={"admin": "A", "action": "0123456789ab"})
    assert r.status_code == 502
    assert "offline" in r.json()["detail"]


def test_key_swap_incident_sticks_until_reset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attack 9's forged key is served only briefly; the mismatch must stay visible."""
    reason = "caught by hub: certificate signature does not verify against the root"
    monkeypatch.setattr(
        actions,
        "attack_swap_key",
        lambda cfg, emit, device, on_swapped=None: actions.AttackResult(
            "swap-key", "BLOCKED", reason, "x"
        ),
    )
    monkeypatch.setattr(actions, "demo_reset", lambda cfg, emit: None)
    client.post("/api/actions/attack.swap_key")
    incidents = client.get("/api/snapshot").json()["trust"]["incidents"]
    assert [i["subject"] for i in incidents] == ["thermostat"]
    assert reason in incidents[0]["detail"]
    client.post("/api/actions/demo.reset")
    assert client.get("/api/snapshot").json()["trust"]["incidents"] == []


def test_spy_uses_the_running_identity(cfg: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    """The dashboard container has only the 'dashboard' TLS identity, not 'cli'."""
    used = []

    def fake_client(cfg_, identity, **_k):
        used.append(identity)
        raise OSError("stop here")

    monkeypatch.setattr(actions, "make_client", fake_client)
    monkeypatch.setattr(actions, "IDENTITY", "cli")  # restored after the test
    dash.create_app(cfg, start_background=False)  # sets actions.IDENTITY
    with pytest.raises(OSError):
        actions.Spy(cfg, "home/#", lambda t, p: None)
    assert used == ["dashboard"]


def test_unexpected_os_error_is_a_readable_502(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(cfg, emit):
        raise FileNotFoundError("no such file: secrets/tls/identities/x/ca.crt")

    monkeypatch.setattr(actions, "attack_read", broken)
    r = client.post("/api/actions/attack.read")
    assert r.status_code == 502
    assert "no such file" in r.json()["detail"]
