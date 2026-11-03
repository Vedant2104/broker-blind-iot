"""Dashboard backend: FastAPI + WebSocket.

- Broker feed: subscribes to Mosquitto itself (what the broker sees).
- Device feed: polls each device's simulator control API for accepted/rejected events.
- Actions: a fixed allowlist, each mapped to the same function the `bbiot` CLI
  calls, with validated parameters. No shell, no free-text commands.
"""

from __future__ import annotations

import asyncio
import itertools
import os
import ssl
import threading
import time
import uuid
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from cli import actions, pki_actions, remote
from securelib.config import Config
from securelib.log import get_logger
from securelib.pki import TrustError
from securelib.services import DirectoryClient, LogClient, ServiceError

log = get_logger("dashboard")
IDENTITY = "dashboard"


# --- live state + broadcast -------------------------------------------------------------


class Live:
    """Recent feeds and a thread-safe fan-out to WebSocket clients."""

    def __init__(self) -> None:
        self.broker_feed: deque[dict] = deque(maxlen=200)
        self.device_feed: deque[dict] = deque(maxlen=300)
        self.alerts: deque[dict] = deque(maxlen=200)
        self.devices: dict[str, dict] = {}
        self.results: list[dict] = []
        self.services = {
            "broker": "unknown",
            "evil-broker": "unknown",
            "directory": "unknown",
            "translog": "unknown",
        }
        self.log_size: int | None = None
        self._queues: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ids = itertools.count(1)

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._queues.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._queues.discard(q)

    def push(self, msg: dict) -> None:
        if self._loop is None:
            return
        for q in list(self._queues):
            self._loop.call_soon_threadsafe(_put_nowait, q, msg)

    def alert(self, severity: str, title: str, **details: Any) -> None:
        item = {
            "id": next(self._ids),
            "ts": time.time(),
            "severity": severity,
            "title": title,
            **details,
        }
        self.alerts.append(item)
        self.push({"type": "alert", "alert": item})

    def snapshot(self) -> dict:
        return {
            "type": "snapshot",
            "security": "off",
            "keymode": "centralized",
            "epoch": None,
            "log_size": self.log_size,
            "services": self.services,
            "devices": self.devices,
            "broker_feed": list(self.broker_feed),
            "device_feed": list(self.device_feed),
            "alerts": list(self.alerts),
            "results": self.results,
        }


def _put_nowait(q: asyncio.Queue, msg: dict) -> None:
    if not q.full():
        q.put_nowait(msg)


def _start_broker_feed(cfg: Config, live: Live) -> None:
    def on_message(topic: str, payload: bytes) -> None:
        item = {
            "ts": time.time(),
            "topic": topic,
            "size": len(payload),
            "payload": actions.format_payload(payload, limit=160),
        }
        live.broker_feed.append(item)
        live.push({"type": "broker", "item": item})

    def run() -> None:
        # Retry until the first connection works; after that paho's background
        # loop reconnects on its own (and re-subscribes in on_connect).
        while True:
            try:
                spy = actions.Spy(cfg, "home/#", on_message, identity="dashboard")
                break
            except OSError as exc:
                live.services["broker"] = "down"
                log.info(f"broker feed unavailable ({exc}); retrying")
                time.sleep(3)
        log.info(f"broker feed: watching home/# on {cfg.mosquitto_host}")
        while True:
            live.services["broker"] = "up" if spy.client.is_connected() else "down"
            time.sleep(1)

    threading.Thread(target=run, daemon=True, name="broker-feed").start()


def _start_device_poller(cfg: Config, live: Live) -> None:
    marks = dict.fromkeys(cfg.devices, 0)

    def poll_once() -> None:
        for dev in cfg.devices:
            try:
                snap = remote.device_state(cfg, dev)
                events = remote.device_events(cfg, dev, after=marks[dev])
            except remote.RemoteError:
                if live.devices.get(dev, {}).get("reachable", True):
                    live.devices[dev] = {"id": dev, "reachable": False}
                    live.push({"type": "device", "device": live.devices[dev]})
                continue
            snap["reachable"] = True
            snap.pop("last_event", None)
            if live.devices.get(dev) != snap:
                live.devices[dev] = snap
                live.push({"type": "device", "device": snap})
            for ev in events:
                marks[dev] = max(marks[dev], ev["id"])
                if ev["kind"] == "alert":
                    live.alert(ev["severity"], ev["title"], reason=ev["reason"], device=dev)
                    continue
                if ev["kind"] not in ("accepted", "rejected"):
                    continue
                item = {"device": dev, **ev}
                live.device_feed.append(item)
                live.push({"type": "device_event", "item": item})
                if ev["kind"] == "rejected":
                    live.alert(
                        "warning",
                        f"{dev} rejected a message",
                        reason=ev.get("reason"),
                        topic=ev.get("topic"),
                    )
        try:
            remote.proxy_status(cfg)
            live.services["evil-broker"] = "up"
        except remote.RemoteError:
            live.services["evil-broker"] = "down"
        _poll_trust_services(cfg, live)

    def run() -> None:
        while True:
            poll_once()
            time.sleep(0.5)

    threading.Thread(target=run, daemon=True, name="device-poller").start()


_clients: dict[str, Any] = {}


def _poll_trust_services(cfg: Config, live: Live) -> None:
    """Directory and log liveness (+ current log size) for the status pills."""
    try:
        if "dir" not in _clients:
            _clients["dir"] = DirectoryClient.connect(cfg, IDENTITY)
            _clients["log"] = LogClient.connect(cfg, IDENTITY)
    except (OSError, ssl.SSLError):
        live.services["directory"] = live.services["translog"] = "down"
        return
    for name, probe in (
        ("directory", lambda: _clients["dir"].list_certs()),
        ("translog", lambda: _clients["log"].sth()),
    ):
        try:
            result = probe()
            live.services[name] = "up"
            if name == "translog":
                size = result["tree_size"]
                if size != live.log_size:
                    live.log_size = size
                    live.push({"type": "log", "size": size})
        except ServiceError:
            live.services[name] = "down"


# --- action allowlist ----------------------------------------------------------------------


class NoParams(BaseModel):
    pass


class SetpointParams(BaseModel):
    setpoint: float = Field(21.0, ge=5, le=35)


class ModifyParams(BaseModel):
    setpoint: float = Field(30.0, ge=5, le=35)


class ReplayParams(BaseModel):
    seq: int | None = Field(None, ge=1)


@dataclass(frozen=True)
class ActionSpec:
    params: type[BaseModel]
    command: Callable[[Any], str]
    run: Callable[[Config, Any, actions.Emit], Any]


FRONT, BACK = "home/door/front/cmd", "home/door/back/cmd"
THERMO = "home/thermostat/living/cmd"
SMOKE_CMD, SMOKE = "home/smoke/kitchen/cmd", "home/smoke/kitchen"


def _send_spec(topic: str, cmd: str) -> ActionSpec:
    return ActionSpec(
        NoParams,
        lambda p: f"bbiot send --device phone --topic {topic} --cmd {cmd}",
        lambda cfg, p, emit: actions.send(cfg, "phone", topic, cmd, {}, emit),
    )


ACTIONS: dict[str, ActionSpec] = {
    "phone.unlock_front": _send_spec(FRONT, "unlock"),
    "phone.lock_front": _send_spec(FRONT, "lock"),
    "phone.unlock_back": _send_spec(BACK, "unlock"),
    "phone.lock_back": _send_spec(BACK, "lock"),
    "phone.test_smoke": _send_spec(SMOKE_CMD, "test"),
    "phone.set_thermostat": ActionSpec(
        SetpointParams,
        lambda p: f"bbiot send --device phone --topic {THERMO} --cmd set --setpoint {p.setpoint:g}",
        lambda cfg, p, emit: actions.send(
            cfg, "phone", THERMO, "set", {"setpoint": p.setpoint}, emit
        ),
    ),
    "attack.read": ActionSpec(
        NoParams, lambda p: "bbiot attack read", lambda cfg, p, emit: actions.attack_read(cfg, emit)
    ),
    "attack.modify": ActionSpec(
        ModifyParams,
        lambda p: f"bbiot attack modify --setpoint {p.setpoint:g}",
        lambda cfg, p, emit: actions.attack_modify(cfg, emit, p.setpoint),
    ),
    "attack.replay": ActionSpec(
        ReplayParams,
        lambda p: "bbiot attack replay" + (f" --seq {p.seq}" if p.seq else ""),
        lambda cfg, p, emit: actions.attack_replay(cfg, emit, p.seq, FRONT),
    ),
    "attack.redirect": ActionSpec(
        NoParams,
        lambda p: f"bbiot attack redirect --from {FRONT} --to {BACK}",
        lambda cfg, p, emit: actions.attack_redirect(cfg, emit, FRONT, BACK),
    ),
    "attack.drop": ActionSpec(
        NoParams,
        lambda p: f"bbiot attack drop --topic {SMOKE}",
        lambda cfg, p, emit: actions.attack_drop(cfg, emit, SMOKE),
    ),
    "log.verify": ActionSpec(
        NoParams,
        lambda p: "bbiot log verify",
        lambda cfg, p, emit: pki_actions.log_verify(cfg, emit, identity=IDENTITY),
    ),
    "demo.reset": ActionSpec(
        NoParams, lambda p: "bbiot demo reset", lambda cfg, p, emit: actions.demo_reset(cfg, emit)
    ),
}


# --- app -----------------------------------------------------------------------------------------


def create_app(cfg: Config, *, start_background: bool = True) -> FastAPI:
    live = Live()
    run_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        live.bind(asyncio.get_running_loop())
        if start_background:
            _start_broker_feed(cfg, live)
            _start_device_poller(cfg, live)
        yield

    app = FastAPI(title="Broker-Blind IoT dashboard", lifespan=lifespan)
    app.state.live = live

    @app.get("/api/snapshot")
    def snapshot() -> dict:
        return live.snapshot()

    @app.get("/api/actions")
    def list_actions() -> list[str]:
        return sorted(ACTIONS)

    @app.post("/api/actions/{name}")
    async def run_action(name: str, body: dict[str, Any] | None = None) -> dict:
        spec = ACTIONS.get(name)
        if spec is None:
            raise HTTPException(404, f"unknown action {name!r}")
        try:
            params = spec.params.model_validate(body or {})
        except ValidationError as exc:
            raise HTTPException(422, exc.errors(include_url=False)) from exc

        run_id = uuid.uuid4().hex[:8]
        command = spec.command(params)

        def emit(line: str) -> None:
            live.push({"type": "console", "run": run_id, "action": name, "line": line})

        def work() -> Any:
            if not run_lock.acquire(timeout=30):
                raise HTTPException(409, "another action is still running")
            try:
                emit(f"$ {command}")
                return spec.run(cfg, params, emit)
            finally:
                run_lock.release()

        try:
            result = await run_in_threadpool(work)
        except (remote.RemoteError, ServiceError, TrustError) as exc:
            emit(f"✗ {exc}")
            raise HTTPException(502, str(exc)) from exc

        payload: dict[str, Any] = {"run": run_id, "action": name, "command": command}
        if isinstance(result, bool):
            payload["ok"] = result
            if not result:
                live.alert("critical", f"'{command}' found problems", command=command)
        if isinstance(result, actions.AttackResult):
            payload["result"] = result.as_dict()
            live.results.append({**result.as_dict(), "security": "off", "ts": time.time()})
            emit(f"[attacker] RESULT: {result.outcome} — {result.reason}")
            severity = "critical" if result.outcome == "SUCCEEDED" else "info"
            live.alert(
                severity,
                f"Attack '{result.attack}' {result.outcome.lower()}",
                reason=result.reason,
                command=command,
            )
        live.push({"type": "action_done", **payload})
        return payload

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        q = live.subscribe()
        try:
            await socket.send_json(live.snapshot())
            while True:
                await socket.send_json(await q.get())
        except WebSocketDisconnect:
            pass
        finally:
            live.unsubscribe(q)

    static = Path(os.environ.get("BBIOT_DASHBOARD_STATIC", "dashboard/web/dist"))
    if static.is_dir():
        app.mount("/", StaticFiles(directory=static, html=True), name="web")

    return app
