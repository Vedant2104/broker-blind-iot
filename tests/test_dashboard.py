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
    assert all(
        name.split(".")[0] in {"phone", "attack", "demo", "log", "security", "keymode"}
        for name in dash.ACTIONS
    )


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
