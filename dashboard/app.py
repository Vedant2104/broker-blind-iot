"""Dashboard backend: FastAPI + WebSocket.

- Broker feed: subscribes to Mosquitto itself (what the broker sees).
- Device feed: polls each device's simulator control API for accepted/rejected events.
- Log tails: the last log lines of every device, the evil broker and the KDC
  (Terminal page), read from their control APIs.
- Trust view: directory entries verified the way a device verifies them (root
  signature, log inclusion, pin), tree head, admin actions, group membership.
- Actions: a fixed allowlist, each mapped to the same function the `bbiot` CLI
  calls, with validated parameters. No shell, no free-text commands. Admin
  approvals go to the admin console (the only holder of admin keys) over mTLS.
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
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from cli import actions, pki_actions, remote
from rootca import approvals
from rootca.console import ConsoleClient, ConsoleError
from securelib.config import Config
from securelib.log import get_logger
from securelib.pki import TrustError
from securelib.services import DirectoryClient, LogClient, ServiceError
from securelib.trust import KeyChanged, PeerVerifier, Revoked

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
        self.console: deque[dict] = deque(maxlen=600)
        self.logs: dict[str, deque[dict]] = {}
        self.trust: dict[str, Any] = {}
        self.log_check: dict[str, Any] | None = None  # last "Verify consistency" result
        self.incidents: list[dict[str, Any]] = []  # trust mismatches seen (until reset)
        self.services = {
            "broker": "unknown",
            "evil-broker": "unknown",
            "directory": "unknown",
            "translog": "unknown",
            "kdc": "unknown",
            "admin-console": "unknown",
        }
        self.log_size: int | None = None
        self.epoch: int | None = None  # KDC epoch
        self.shown_epoch: int | None = None
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

    def security(self) -> str:
        """System security mode as reported by the devices themselves."""
        modes = {d.get("security") for d in self.devices.values() if d.get("reachable")}
        modes.discard(None)
        return modes.pop() if len(modes) == 1 else ("mixed" if modes else "unknown")

    def display_epoch(self) -> int | None:
        """KDC epoch in centralized mode; the MLS epoch (as the devices report it) in
        decentralized mode."""
        if self.keymode() != "decentralized":
            return self.epoch
        epochs = [
            ((d.get("groups") or {}).get("decentralized") or {}).get("epoch")
            for d in self.devices.values()
            if d.get("reachable")
        ]
        epochs = [e for e in epochs if e is not None]
        return max(epochs) if epochs else None

    def keymode(self) -> str:
        modes = {d.get("keymode") for d in self.devices.values() if d.get("reachable")}
        modes.discard(None)
        return modes.pop() if len(modes) == 1 else ("mixed" if modes else "centralized")

    def snapshot(self) -> dict:
        return {
            "type": "snapshot",
            "security": self.security(),
            "keymode": self.keymode(),
            "epoch": self.display_epoch(),
            "log_size": self.log_size,
            "services": self.services,
            "devices": self.devices,
            "broker_feed": list(self.broker_feed),
            "device_feed": list(self.device_feed),
            "alerts": list(self.alerts),
            "results": self.results,
            "console": list(self.console),
            "logs": {src: list(lines) for src, lines in self.logs.items()},
            "trust": self.trust_payload(),
            "log_check": self.log_check,
        }

    def trust_payload(self) -> dict[str, Any]:
        return {**self.trust, "incidents": self.incidents}

    def incident(self, subject: str, detail: str) -> None:
        if any(i["subject"] == subject and i["detail"] == detail for i in self.incidents):
            return
        self.incidents.append({"subject": subject, "detail": detail, "ts": time.time()})
        self.alert("critical", f"Key directory mismatch: {subject}", reason=detail)

    def log_lines(self, source: str, lines: list[dict]) -> None:
        buf = self.logs.setdefault(source, deque(maxlen=300))
        for item in lines:
            entry = {"source": source, "ts": item["ts"], "line": item["line"]}
            buf.append(entry)
        if lines:
            self.push({"type": "logline", "source": source, "lines": [x["line"] for x in lines]})


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
                if dev == "hub" and ev["kind"] == "accepted":
                    continue  # the hub sees everything; its feed would drown the others
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


def _log_sources(cfg: Config) -> dict[str, Callable[[int], list[dict]]]:
    sources: dict[str, Callable[[int], list[dict]]] = {
        dev: (lambda after, d=dev: remote.device_logs(cfg, d, after)) for dev in cfg.devices
    }
    sources["evil-broker"] = lambda after: remote.proxy_logs(cfg, after)
    sources["kdc"] = lambda after: remote.kdc_logs(cfg, after)
    return sources


def _start_log_poller(cfg: Config, live: Live) -> None:
    """Tail every component's log lines for the Terminal page."""
    sources = _log_sources(cfg)
    marks = dict.fromkeys(sources, 0)

    def run() -> None:
        while True:
            for name, fetch in sources.items():
                try:
                    lines = fetch(marks[name])
                except remote.RemoteError:
                    continue
                if lines:
                    if lines[0]["id"] <= marks[name]:  # component restarted
                        live.log_lines(name, [{"ts": time.time(), "line": "--- restarted ---"}])
                    marks[name] = lines[-1]["id"]
                    live.log_lines(name, lines)
            time.sleep(0.7)

    threading.Thread(target=run, daemon=True, name="log-poller").start()


# --- trust view (Keys & Trust page) ------------------------------------------------------------

# Pins and the last-seen tree head live in one state dir; serialize its users.
TRUST_LOCK = threading.Lock()


def _verify_entries(verifier: PeerVerifier, entries: list[dict]) -> list[dict]:
    """Check each directory entry the way a device would (root, revocation, log, pin)."""
    revoked = verifier.revocations()
    rows = []
    for entry in sorted(entries, key=lambda e: e["leaf_index"]):
        dev = entry["device_id"]
        row = {
            "device": dev,
            "fingerprint": entry.get("fingerprint"),
            "leaf_index": entry.get("leaf_index"),
        }
        try:
            peer = verifier.verify(dev, entry, revoked)
            if peer.leaf_index != entry["leaf_index"]:
                raise TrustError(
                    f"directory claims leaf #{entry['leaf_index']}, log says #{peer.leaf_index}"
                )
            row.update(status="verified", pin=peer.pin, detail="root ✓ · log inclusion ✓")
        except Revoked as exc:
            row.update(status="revoked", detail=str(exc))
        except KeyChanged as exc:
            row.update(status="key-changed", detail=str(exc))
        except TrustError as exc:
            row.update(status="invalid", detail=str(exc))
        rows.append(row)
    return rows


def trust_view(
    cfg: Config, verifier: PeerVerifier, console: ConsoleClient | None, live: Live
) -> dict[str, Any]:
    """Everything the Keys & Trust page shows. Public material only: fingerprints,
    tree heads, member names and approval counts — never keys."""
    sth, log_error = None, None
    with TRUST_LOCK:
        try:
            sth, _ = verifier.log.fresh_sth()
        except TrustError as exc:  # forked / rewritten / bad signature
            log_error = str(exc)
        rows = _verify_entries(verifier, verifier.directory.list_certs())
    actions_list = []
    for e in verifier.directory.list_actions():
        actions_list.append(
            {
                "id": e["id"],
                "type": e["action"]["type"],
                "device": e["action"]["device_id"],
                "status": e["status"],
                "approvals": sorted(e["approvals"]),
                "created_ms": e["action"].get("created_ms"),
            }
        )
    actions_list.sort(key=lambda a: a.get("created_ms") or 0, reverse=True)
    view: dict[str, Any] = {
        "ts": time.time(),
        "directory": rows,
        "sth": sth
        and {
            "tree_size": sth.tree_size,
            "root_hash": sth.root_hash.hex(),
            "timestamp_ms": sth.timestamp_ms,
        },
        "log_error": log_error,
        "actions": actions_list[:20],
        "threshold": approvals.THRESHOLD,
        "kdc": None,
        "mls": None,
        "console": None,
    }
    try:
        st = remote.kdc_status(cfg)
        view["kdc"] = {
            "epoch": st["epoch"],
            "members": st["members"],
            "revoked": st.get("revoked", []),
            "history": st.get("history", [])[-6:],
        }
    except remote.RemoteError:
        pass
    admin = live.devices.get(cfg.group_admin) or {}
    mls = (admin.get("groups") or {}).get("decentralized")
    if mls:
        view["mls"] = {k: mls.get(k) for k in ("epoch", "members", "admin", "group_id")}
    if console is not None:
        try:
            view["console"] = console.status()
            live.services["admin-console"] = "up"
        except (ServiceError, ConsoleError):
            live.services["admin-console"] = "down"
    return view


class TrustWatcher:
    """Builds the trust view every few seconds, or right now on request (e.g. while
    attack 9's forged entry is being served). Mismatches stay listed as incidents
    until the demo is reset, so a short-lived swap is not missed."""

    def __init__(self, cfg: Config, live: Live) -> None:
        self.cfg, self.live = cfg, live
        self.refresh = threading.Event()
        self._verifier: PeerVerifier | None = None
        self._console: ConsoleClient | None = None
        self._lock = threading.Lock()

    def check_now(self) -> None:
        with self._lock:
            try:
                self._verifier = self._verifier or PeerVerifier.for_identity(
                    self.cfg, IDENTITY, self.cfg.state_dir / IDENTITY
                )
                self._console = self._console or ConsoleClient(self.cfg, IDENTITY)
                view = trust_view(self.cfg, self._verifier, self._console, self.live)
            except (OSError, ssl.SSLError, ServiceError, TrustError, KeyError) as exc:
                log.info(f"trust view unavailable ({exc})")
                return
            for row in view["directory"]:
                if row["status"] in ("key-changed", "invalid"):
                    detail = f"directory served a bad entry: {row['detail']}"
                    self.live.incident(row["device"], detail)
            if view["log_error"]:
                self.live.incident("transparency log", view["log_error"])
            self.live.trust = view
            self.live.push({"type": "trust", "trust": self.live.trust_payload()})

    def start(self) -> None:
        def run() -> None:
            while True:
                self.check_now()
                self.refresh.wait(3)
                self.refresh.clear()

        threading.Thread(target=run, daemon=True, name="trust-poller").start()


_watcher: TrustWatcher | None = None  # set by create_app; used by attack 9's hook


def _swap_key(cfg: Config, emit: actions.Emit) -> actions.AttackResult:
    hook = _watcher.check_now if _watcher is not None else None
    return actions.attack_swap_key(cfg, emit, "thermostat", on_swapped=hook)


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
    try:
        st = remote.kdc_status(cfg)
        live.services["kdc"] = "up"
        live.epoch = st["epoch"]
        shown = live.display_epoch()
        if shown != live.shown_epoch:
            live.shown_epoch = shown
            live.push({"type": "epoch", "epoch": shown})
    except remote.RemoteError:
        live.services["kdc"] = "down"


# --- action allowlist ----------------------------------------------------------------------


class NoParams(BaseModel):
    pass


class SetpointParams(BaseModel):
    setpoint: float = Field(21.0, ge=5, le=35)


class ModifyParams(BaseModel):
    setpoint: float = Field(30.0, ge=5, le=35)


class MitmParams(BaseModel):
    unsigned: bool | None = None  # default: unsigned when security is OFF, signed when ON


class ReplayParams(BaseModel):
    seq: int | None = Field(None, ge=1)


class PairParams(BaseModel):
    # checked against home.yaml in run_action
    device: str = Field("garage-lock", pattern=r"^[a-z][a-z0-9-]{1,31}$")


class ApproveParams(BaseModel):
    admin: Literal["A", "B", "C"]
    action: str = Field(pattern=r"^[0-9a-f]{12}$")


def _pair(cfg: Config, device: str, emit: actions.Emit) -> dict[str, Any]:
    """`bbiot pair`, plus the two codes for the Pairing page's comparison step."""
    action_id = pki_actions.pair(cfg, device, emit, identity=IDENTITY)
    info = remote.device_identity(cfg, device)
    return {
        "device": device,
        "action_id": action_id,
        "request_code": pki_actions.inspect_csr(info["csr_pem"].encode(), device),
        "device_code": info["pairing_code"],
        "fingerprint": info["fingerprint"],
    }


def _approve(cfg: Config, admin: str, action_id: str, emit: actions.Emit) -> dict[str, Any]:
    """`bbiot admin approve`, signed by the admin console (the only holder of admin keys)."""
    try:
        result = ConsoleClient(cfg, IDENTITY).approve(admin, action_id)
    except ConsoleError as exc:
        for line in exc.args[1] if len(exc.args) > 1 else []:
            emit(line)
        raise ServiceError(str(exc.args[0])) from exc
    for line in result["lines"]:
        emit(line)
    return {"action_id": action_id, "admin": admin, "issued": result["issued"]}


def _log_verify(cfg: Config, emit: actions.Emit) -> bool:
    with TRUST_LOCK:
        return pki_actions.log_verify(cfg, emit, identity=IDENTITY)


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
        NoParams, lambda p: "bbiot log verify", lambda cfg, p, emit: _log_verify(cfg, emit)
    ),
    "pair.start": ActionSpec(
        PairParams,
        lambda p: f"bbiot pair --device {p.device}",
        lambda cfg, p, emit: _pair(cfg, p.device, emit),
    ),
    "pair.revoke": ActionSpec(
        PairParams,
        lambda p: f"bbiot revoke --device {p.device}",
        lambda cfg, p, emit: {
            "device": p.device,
            "action_id": pki_actions.revoke(cfg, p.device, emit, identity=IDENTITY),
        },
    ),
    "admin.approve": ActionSpec(
        ApproveParams,
        lambda p: f"bbiot admin approve --admin {p.admin} --action {p.action}",
        lambda cfg, p, emit: _approve(cfg, p.admin, p.action, emit),
    ),
    "attack.mitm_dh": ActionSpec(
        MitmParams,
        lambda p: "bbiot attack mitm-dh" + (" --unsigned" if p.unsigned else ""),
        lambda cfg, p, emit: actions.attack_mitm_dh(cfg, emit, bool(p.unsigned)),
    ),
    "attack.swap_key": ActionSpec(
        NoParams,
        lambda p: "bbiot attack swap-key --device thermostat",
        lambda cfg, p, emit: _swap_key(cfg, emit),
    ),
    "attack.kdc_vs_directory": ActionSpec(
        NoParams,
        lambda p: "bbiot attack kdc-vs-directory",
        lambda cfg, p, emit: actions.attack_kdc_vs_directory(cfg, emit),
    ),
    "keymode.centralized": ActionSpec(
        NoParams,
        lambda p: "bbiot keymode centralized",
        lambda cfg, p, emit: actions.set_keymode(cfg, "centralized", emit),
    ),
    "keymode.decentralized": ActionSpec(
        NoParams,
        lambda p: "bbiot keymode decentralized",
        lambda cfg, p, emit: actions.set_keymode(cfg, "decentralized", emit),
    ),
    "attack.compromised_device": ActionSpec(
        NoParams,
        lambda p: "bbiot attack compromised-device --device thermostat",
        lambda cfg, p, emit: actions.attack_compromised_device(cfg, emit, "thermostat"),
    ),
    "attack.counterfeit": ActionSpec(
        NoParams,
        lambda p: "bbiot attack counterfeit",
        lambda cfg, p, emit: actions.attack_counterfeit(cfg, emit),
    ),
    "security.on": ActionSpec(
        NoParams,
        lambda p: "bbiot security on",
        lambda cfg, p, emit: actions.set_security(cfg, "on", emit),
    ),
    "security.off": ActionSpec(
        NoParams,
        lambda p: "bbiot security off",
        lambda cfg, p, emit: actions.set_security(cfg, "off", emit),
    ),
    "demo.reset": ActionSpec(
        NoParams, lambda p: "bbiot demo reset", lambda cfg, p, emit: actions.demo_reset(cfg, emit)
    ),
}


# --- app -----------------------------------------------------------------------------------------


def create_app(cfg: Config, *, start_background: bool = True) -> FastAPI:
    actions.IDENTITY = IDENTITY  # shared actions connect as the dashboard's TLS identity
    live = Live()
    run_lock = threading.Lock()
    watcher = TrustWatcher(cfg, live)
    if start_background:
        global _watcher
        _watcher = watcher

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        live.bind(asyncio.get_running_loop())
        if start_background:
            _start_broker_feed(cfg, live)
            _start_device_poller(cfg, live)
            _start_log_poller(cfg, live)
            watcher.start()
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
        if isinstance(params, PairParams) and params.device not in cfg.devices:
            raise HTTPException(422, f"unknown device {params.device!r}")

        run_id = uuid.uuid4().hex[:8]
        mode_at_launch = live.security()
        keymode_at_launch = live.keymode()
        if isinstance(params, MitmParams) and params.unsigned is None:
            params.unsigned = mode_at_launch == "off"
        command = spec.command(params)

        def emit(line: str) -> None:
            item = {"run": run_id, "action": name, "line": line, "ts": time.time()}
            live.console.append(item)
            live.push({"type": "console", **item})

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
            live.push({"type": "action_done", "run": run_id, "action": name, "error": str(exc)})
            raise HTTPException(502, str(exc)) from exc
        finally:
            watcher.refresh.set()

        payload: dict[str, Any] = {"run": run_id, "action": name, "command": command}
        if isinstance(result, dict):
            payload["data"] = result
        if isinstance(result, bool):
            payload["ok"] = result
            if name == "log.verify":
                live.log_check = {"ok": result, "ts": time.time()}
            if not result:
                live.alert("critical", f"'{command}' found problems", command=command)
        if isinstance(result, actions.AttackResult):
            # the mode it ran under, for the attack x mode results matrix
            recorded = {
                **result.as_dict(),
                "security": mode_at_launch,
                "keymode": keymode_at_launch,
                "ts": time.time(),
            }
            payload["result"] = recorded
            live.results.append(recorded)
            if result.attack == "swap-key":  # also covers MLS key packages (not in the table)
                live.incident("thermostat", f"attack 9 {result.outcome.lower()}: {result.reason}")
            emit(f"[attacker] RESULT: {result.outcome} — {result.reason}")
            severity = "critical" if result.outcome == "SUCCEEDED" else "info"
            live.alert(
                severity,
                f"Attack '{result.attack}' {result.outcome.lower()}",
                reason=result.reason,
                command=command,
            )
        if name == "demo.reset":
            live.incidents.clear()
            live.log_check = None
            live.push({"type": "trust", "trust": live.trust_payload()})
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
