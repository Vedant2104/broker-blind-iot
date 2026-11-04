"""Broker health checks over mTLS: a publish/subscribe round trip, and proof
that a client without a certificate is turned away."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

from securelib.config import Config
from securelib.mqtt import make_client


@dataclass
class CheckResult:
    ok: bool
    detail: str


def roundtrip(cfg: Config, identity: str, timeout: float = 5.0) -> CheckResult:
    """Connect with a client cert, publish to a random topic and receive it back."""
    topic = f"bbiot/selftest/{uuid.uuid4().hex[:8]}"
    connected, subscribed, received = threading.Event(), threading.Event(), threading.Event()
    state: dict[str, object] = {}

    client = make_client(cfg, identity)
    client.on_connect = lambda c, u, f, rc, p: (state.update(rc=rc), connected.set())
    client.on_subscribe = lambda c, u, mid, rcs, p: subscribed.set()
    client.on_message = lambda c, u, msg: (state.update(t=time.perf_counter()), received.set())

    try:
        client.connect(cfg.broker_host, cfg.broker_port, keepalive=10)
    except OSError as exc:
        return CheckResult(False, f"cannot connect to {cfg.broker_host}:{cfg.broker_port}: {exc}")

    client.loop_start()
    try:
        if not connected.wait(timeout) or getattr(state.get("rc"), "is_failure", True):
            return CheckResult(False, f"CONNACK failed: {state.get('rc')}")
        client.subscribe(topic, qos=1)
        if not subscribed.wait(timeout):
            return CheckResult(False, "SUBACK timed out")
        start = time.perf_counter()
        client.publish(topic, b"ping", qos=1)
        if not received.wait(timeout):
            return CheckResult(False, "message not echoed back")
        ms = (float(state["t"]) - start) * 1000  # type: ignore[arg-type]
        return CheckResult(True, f"mTLS round trip as '{identity}' in {ms:.1f} ms")
    finally:
        client.disconnect()
        client.loop_stop()


def rejects_without_cert(cfg: Config, identity: str, timeout: float = 5.0) -> CheckResult:
    """Connect WITHOUT a client certificate. The broker must refuse."""
    connected = threading.Event()
    state: dict[str, object] = {}

    client = make_client(cfg, identity, client_cert=False)
    client.on_connect = lambda c, u, f, rc, p: (state.update(rc=rc), connected.set())
    try:
        client.connect(cfg.broker_host, cfg.broker_port, keepalive=10)
    except OSError as exc:
        return CheckResult(True, f"rejected during TLS handshake ({type(exc).__name__})")

    client.loop_start()
    try:
        connected.wait(timeout)
        rc = state.get("rc")
        if rc is not None and not rc.is_failure:  # type: ignore[attr-defined]
            return CheckResult(False, "broker ACCEPTED a client with no certificate")
        return CheckResult(True, "rejected (no CONNACK success without a client cert)")
    finally:
        client.disconnect()
        client.loop_stop()


# --- pre-demo checklist ----------------------------------------------------------------------


def preflight(cfg: Config, identity: str) -> list[tuple[str, CheckResult, bool]]:
    """Everything a live demo needs. Returns (name, result, required)."""
    from cli import remote
    from rootca.console import ConsoleClient, ConsoleError
    from securelib.services import DirectoryClient, LogClient, ServiceError

    out: list[tuple[str, CheckResult, bool]] = []

    def check(name: str, fn, required: bool = True) -> None:
        try:
            out.append((name, fn(), required))
        except Exception as exc:  # noqa: BLE001 - every failure is a finding
            out.append((name, CheckResult(False, f"{type(exc).__name__}: {exc}"), required))

    check("broker: mTLS round trip", lambda: roundtrip(cfg, identity))
    check("broker: client without cert refused", lambda: rejects_without_cert(cfg, identity))

    def evil() -> CheckResult:
        rules = remote.proxy_status(cfg)["rules"]
        armed = {k: v for k, v in rules.items() if v}
        if armed:
            return CheckResult(False, f"attack rules still armed: {armed} (bbiot demo reset)")
        return CheckResult(True, "reachable, no attack armed")

    check("evil broker", evil)

    def directory() -> CheckResult:
        n = len(DirectoryClient.connect(cfg, identity).list_certs())
        return CheckResult(True, f"{n} certificates")

    def translog() -> CheckResult:
        return CheckResult(True, f"tree size {LogClient.connect(cfg, identity).sth()['tree_size']}")

    def kdc() -> CheckResult:
        st = remote.kdc_status(cfg)
        return CheckResult(True, f"epoch {st['epoch']}, {len(st['members'])} members")

    def console() -> CheckResult:
        try:
            st = ConsoleClient(cfg, identity).status()
        except (ServiceError, ConsoleError) as exc:
            return CheckResult(False, f"{exc} — dashboard approvals off, CLI still works")
        return CheckResult(True, f"admin keys {', '.join(st['admins'])}")

    check("key directory", directory)
    check("transparency log", translog)
    check("KDC", kdc)
    check("admin console", console, required=False)

    modes: set[tuple[str, str]] = set()
    quarantined: list[str] = []
    for dev in cfg.devices.values():

        def device(dev=dev) -> CheckResult:
            snap = remote.device_state(cfg, dev.id)
            modes.add((snap["security"], snap["keymode"]))
            quarantined.extend(snap.get("quarantined") or [])
            cert = snap["identity"]["cert"]["status"]
            group = (snap.get("groups") or {}).get(snap["keymode"]) or snap.get("group") or {}
            problems = []
            if not snap["connected"]:
                problems.append("not connected to the broker")
            if cert != "trusted":
                problems.append(f"certificate {cert}")
            if snap["security"] == "on" and group.get("epoch") is None and dev.kind != "hub":
                problems.append(f"no {snap['keymode']} group key")
            detail = (
                f"{snap['security'].upper()} · {snap['keymode']} · epoch {group.get('epoch')} · "
                f"cert {cert}"
            )
            if problems:
                return CheckResult(False, "; ".join(problems) + f" ({detail})")
            return CheckResult(True, detail)

        # an uncommissioned device (garage-lock) is fine: it is there to be paired live
        check(f"device {dev.id}", device, required=dev.commissioned)

    def consistent() -> CheckResult:
        if len(modes) > 1:
            return CheckResult(False, f"devices disagree: {sorted(modes)} (wait, or set it again)")
        if quarantined:
            return CheckResult(False, f"quarantined: {sorted(set(quarantined))} (bbiot demo reset)")
        return CheckResult(True, "all devices on the same security and key mode, none quarantined")

    check("home consistent", consistent)
    return out
