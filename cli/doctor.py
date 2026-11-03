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
