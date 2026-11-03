"""bbiot — every action in the system is a command here.

Working: tls init, doctor, status, send, spy, attack read/modify/replay/redirect/drop,
demo reset, and the runners (device/proxy/dashboard run). The remaining commands
take their final arguments and say which phase implements them.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from enum import StrEnum

import typer

from cli import actions, pki_actions, remote
from cli import doctor as doctor_mod
from securelib.config import Config, load_config
from securelib.log import get_logger
from securelib.pki import TrustError
from securelib.services import ServiceError
from securelib.tls import init_tls, tls_material_exists

app = typer.Typer(help="Broker-Blind IoT command line.", no_args_is_help=True)
tls_app = typer.Typer(help="Transport TLS (mTLS) material for the broker.", no_args_is_help=True)
attack_app = typer.Typer(help="Run an attack through the evil-broker proxy.", no_args_is_help=True)
admin_app = typer.Typer(help="Admin approvals (2-of-3 signatures).", no_args_is_help=True)
log_app = typer.Typer(help="Transparency log.", no_args_is_help=True)
bench_app = typer.Typer(help="Benchmarks.", no_args_is_help=True)
demo_app = typer.Typer(help="Demo helpers.", no_args_is_help=True)
device_app = typer.Typer(help="Run a simulated device.", no_args_is_help=True)
proxy_app = typer.Typer(help="The evil-broker proxy.", no_args_is_help=True)
dashboard_app = typer.Typer(help="The web dashboard.", no_args_is_help=True)
pki_app = typer.Typer(help="Offline root ceremony and commissioning.", no_args_is_help=True)
root_app = typer.Typer(help="The offline root CA.", no_args_is_help=True)
service_app = typer.Typer(help="Run a backend service.", no_args_is_help=True)
security_app = typer.Typer(help="End-to-end protection ON / OFF.", no_args_is_help=True)
kdc_app = typer.Typer(help="Key Distribution Center (centralized mode).", no_args_is_help=True)

for sub, name in [
    (tls_app, "tls"),
    (attack_app, "attack"),
    (admin_app, "admin"),
    (log_app, "log"),
    (bench_app, "bench"),
    (demo_app, "demo"),
    (device_app, "device"),
    (proxy_app, "proxy"),
    (dashboard_app, "dashboard"),
    (pki_app, "pki"),
    (root_app, "root"),
    (service_app, "run"),
    (security_app, "security"),
    (kdc_app, "kdc"),
]:
    app.add_typer(sub, name=name)

log = get_logger("cli")


class Admin(StrEnum):
    A = "A"
    B = "B"
    C = "C"


def _cfg() -> Config:
    return load_config()


def _emit(line: str) -> None:
    print(line, flush=True)


def _todo(phase: int, what: str) -> None:
    log.info(f"'{what}' is not implemented yet (planned for phase {phase})")
    raise typer.Exit(code=2)


def _check_device(cfg: Config, device: str) -> None:
    if device not in cfg.devices:
        raise typer.BadParameter(f"unknown device '{device}'. Known: {', '.join(cfg.devices)}")


def _check_topic(cfg: Config, topic: str, *, allow_wildcard: bool = False) -> None:
    if allow_wildcard and topic in ("#", "home/#"):
        return
    if topic not in cfg.topics:
        raise typer.BadParameter(f"unknown topic '{topic}'. Known: {', '.join(cfg.topics)}")


def _run_remote(fn: Callable[[], object]) -> object:
    """Run an action, turning unreachable services into a clean error."""
    try:
        return fn()
    except remote.RemoteError as exc:
        log.info(f"✗ {exc}")
        if isinstance(exc, remote.Unreachable):
            log.info("is the stack running? try: docker compose up -d")
        raise typer.Exit(code=1) from exc


def _report(result: actions.AttackResult) -> None:
    mark = {"SUCCEEDED": "☠", "BLOCKED": "🛡", "DETECTED": "🔔"}.get(result.outcome, "?")
    _emit(f"[attacker] {mark} RESULT: {result.outcome} — {result.reason}")


# --- setup / health ---------------------------------------------------------------


@tls_app.command("init")
def tls_init(
    force: bool = typer.Option(False, "--force", help="Regenerate everything, including the CA."),
    if_missing: bool = typer.Option(False, "--if-missing", help="Do nothing if a CA exists."),
) -> None:
    """Create the transport CA, broker cert and one client cert per device/service."""
    cfg = _cfg()
    if if_missing and tls_material_exists(cfg.tls_dir) and not force:
        log.info(
            f"TLS material already present in {cfg.tls_dir}, keeping it; adding new identities"
        )
    uid = os.environ.get("BBIOT_BROKER_KEY_UID")
    written = init_tls(
        cfg.tls_dir, cfg.identities, force=force, broker_key_uid=int(uid) if uid else None
    )
    for path in written:
        log.info(f"wrote {path.as_posix()}")
    log.info(f"{len(written)} certificate(s) written, {len(cfg.identities)} client identities")


@app.command()
def doctor(
    identity: str = typer.Option("cli", help="Client identity to connect as."),
) -> None:
    """Check the broker: mTLS round trip works, and no-certificate clients are refused."""
    cfg = _cfg()
    log.info(f"broker {cfg.broker_host}:{cfg.broker_port}")
    checks = [
        ("round trip with client cert", doctor_mod.roundtrip(cfg, identity)),
        ("connect without client cert", doctor_mod.rejects_without_cert(cfg, identity)),
    ]
    for name, result in checks:
        mark = "✓" if result.ok else "✗"
        log.info(f"{mark} {name}: {result.detail}")
    if not all(r.ok for _, r in checks):
        raise typer.Exit(code=1)


@app.command()
def status() -> None:
    """Show every device's state and the evil broker's armed rules."""
    cfg = _cfg()
    for dev in cfg.devices:
        try:
            snap = remote.device_state(cfg, dev)
            conn = "online " if snap["connected"] else "OFFLINE"
            _emit(f"[status] {dev:<14} {conn} security={snap['security']}  {snap['state']}")
        except remote.RemoteError:
            _emit(f"[status] {dev:<14} unreachable")
    try:
        st = remote.proxy_status(cfg)
        _emit(f"[status] evil-broker   rules={st['rules']} stats={st['stats']}")
    except remote.RemoteError:
        _emit("[status] evil-broker   unreachable")


# --- device actions ---------------------------------------------------------------


@app.command()
def send(
    device: str = typer.Option(..., help="Sending device, e.g. phone."),
    topic: str = typer.Option(..., help="Topic, e.g. home/door/front/cmd."),
    cmd: str = typer.Option(..., help="Command: lock, unlock, set, test."),
    setpoint: float | None = typer.Option(None, help="Setpoint for cmd=set."),
) -> None:
    """Ask a device to send a command."""
    cfg = _cfg()
    _check_device(cfg, device)
    _check_topic(cfg, topic)
    args = {"setpoint": setpoint} if setpoint is not None else {}
    _run_remote(lambda: actions.send(cfg, device, topic, cmd, args, _emit))


@app.command()
def spy(
    topic: str = typer.Option("home/#", help="Topic filter."),
    seconds: float = typer.Option(0, help="Stop after this many seconds (0 = until Ctrl+C)."),
) -> None:
    """Show what the broker sees (subscribes to Mosquitto itself)."""
    cfg = _cfg()
    _check_topic(cfg, topic, allow_wildcard=True)
    spy_ = actions.Spy(cfg, topic, lambda t, p: _emit(actions.spy_line(t, p)))
    _emit(f"[spy] watching {topic} on Mosquitto {cfg.mosquitto_host}:{cfg.mosquitto_port}")
    try:
        deadline = time.monotonic() + seconds if seconds else None
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        spy_.close()


# --- attacks ------------------------------------------------------------------------


@attack_app.command("read")
def attack_read() -> None:
    """1. Broker reads payloads."""
    cfg = _cfg()
    _report(_run_remote(lambda: actions.attack_read(cfg, _emit)))  # type: ignore[arg-type]


@attack_app.command("modify")
def attack_modify(
    setpoint: float = typer.Option(30.0, help="Setpoint the broker injects."),
    requested: float = typer.Option(21.0, help="Setpoint the phone asks for."),
) -> None:
    """2. Broker modifies a thermostat setpoint."""
    cfg = _cfg()
    result = _run_remote(lambda: actions.attack_modify(cfg, _emit, setpoint, requested))
    _report(result)  # type: ignore[arg-type]


@attack_app.command("replay")
def attack_replay(
    seq: int | None = typer.Option(None, help="Seq of a captured message (default: capture one)."),
    topic: str = typer.Option("home/door/front/cmd", help="Command topic to replay on."),
) -> None:
    """3. Broker replays a captured 'unlock front door'."""
    cfg = _cfg()
    _check_topic(cfg, topic)
    _report(_run_remote(lambda: actions.attack_replay(cfg, _emit, seq, topic)))  # type: ignore[arg-type]


@attack_app.command("redirect")
def attack_redirect(
    from_topic: str = typer.Option("home/door/front/cmd", "--from", help="Original topic."),
    to_topic: str = typer.Option("home/door/back/cmd", "--to", help="Topic to redirect to."),
) -> None:
    """4. Broker redirects a command to another device's topic."""
    cfg = _cfg()
    _check_topic(cfg, from_topic)
    _check_topic(cfg, to_topic)
    result = _run_remote(lambda: actions.attack_redirect(cfg, _emit, from_topic, to_topic))
    _report(result)  # type: ignore[arg-type]


@attack_app.command("drop")
def attack_drop(
    topic: str = typer.Option("home/smoke/kitchen", help="Topic whose messages are dropped."),
) -> None:
    """5. Broker silently drops messages (default: the smoke alarm)."""
    cfg = _cfg()
    _check_topic(cfg, topic)
    _report(_run_remote(lambda: actions.attack_drop(cfg, _emit, topic)))  # type: ignore[arg-type]


@attack_app.command("mitm-dh")
def attack_mitm_dh(
    unsigned: bool = typer.Option(False, "--unsigned", help="Use the insecure unsigned DH."),
    victim: str = typer.Option("thermostat", help="Device whose key exchange is attacked."),
) -> None:
    """6. Broker MITMs the device <-> KDC key exchange (unsigned: key stolen; signed: caught)."""
    cfg = _cfg()
    _check_device(cfg, victim)
    _report(_run_remote(lambda: actions.attack_mitm_dh(cfg, _emit, unsigned, victim)))  # type: ignore[arg-type]


@attack_app.command("compromised-device")
def attack_compromised_device(
    device: str = typer.Option("thermostat", help="Device that turns malicious."),
) -> None:
    """7. Compromised device subscribes to door topics -> quarantine + rekey."""
    _check_device(_cfg(), device)
    _todo(6, "attack compromised-device")


@attack_app.command("counterfeit")
def attack_counterfeit() -> None:
    """8. Counterfeit device tries to join."""
    _todo(6, "attack counterfeit")


@attack_app.command("swap-key")
def attack_swap_key(
    device: str = typer.Option(..., help="Device whose key is substituted."),
) -> None:
    """9. Compromised directory substitutes a public key."""
    _check_device(_cfg(), device)
    _todo(5, "attack swap-key")


@attack_app.command("kdc-vs-directory")
def attack_kdc_vs_directory() -> None:
    """10. Compromised KDC (centralized) vs. compromised directory (decentralized)."""
    _todo(5, "attack kdc-vs-directory")


# --- PKI / admin / log / bench (later phases) ---------------------------------------------


def _run_pki(fn: Callable[[], object]) -> object:
    """Run a PKI workflow; trust failures and unreachable services exit cleanly."""
    try:
        return fn()
    except TrustError as exc:
        log.info(f"✗ REFUSED: {exc}")
        raise typer.Exit(code=1) from exc
    except (ServiceError, remote.RemoteError) as exc:
        log.info(f"✗ {exc}")
        log.info("is the stack running? try: docker compose up -d")
        raise typer.Exit(code=1) from exc


@pki_app.command("init")
def pki_init(
    force: bool = typer.Option(False, "--force", help="Replace the whole PKI (new root!)."),
) -> None:
    """Offline ceremony: create the root, admin keys A/B/C and the log key."""
    cfg = _cfg()
    _run_pki(lambda: pki_actions.pki_init(cfg, _emit, force=force))


@pki_app.command("bootstrap")
def pki_bootstrap() -> None:
    """Commission every device marked commissioned in home.yaml (admins A + B)."""
    cfg = _cfg()
    _run_pki(lambda: pki_actions.bootstrap(cfg, _emit))


@app.command()
def pair(device: str = typer.Option(..., help="Device id, e.g. garage-lock.")) -> None:
    """Pair a device: verify its request, compare codes, ask admins to approve."""
    cfg = _cfg()
    _check_device(cfg, device)
    _run_pki(lambda: pki_actions.pair(cfg, device, _emit))


@admin_app.command("approve")
def admin_approve(
    admin: Admin = typer.Option(..., help="Approving admin."),
    action: str = typer.Option(..., help="Pending action id."),
) -> None:
    """Sign a pending admin action; at 2 of 3 the offline root issues the cert."""
    cfg = _cfg()
    _run_pki(lambda: pki_actions.approve(cfg, admin.value, action, _emit))


@admin_app.command("list")
def admin_list() -> None:
    """Show admin actions on the directory's bulletin board."""
    cfg = _cfg()
    entries = _run_pki(lambda: pki_actions.directory(cfg).list_actions())
    for e in entries:  # type: ignore[union-attr]
        a = e["action"]
        signed = ", ".join(sorted(e["approvals"])) or "-"
        _emit(
            f"[admin] {e['id']}  {a['type']:<13} {a['device_id']:<14} {e['status']:<8} "
            f"approved by: {signed}"
        )


@root_app.command("issue")
def root_issue(action: str = typer.Option(..., help="Approved action id.")) -> None:
    """Have the offline root sign the certificate for an approved action."""
    cfg = _cfg()
    _run_pki(lambda: pki_actions.issue(cfg, action, _emit))


@app.command()
def revoke(device: str = typer.Option(..., help="Device to remove from the home.")) -> None:
    """Revoke a device (2 of 3 admins) — the KDC removes it and rekeys."""
    cfg = _cfg()
    _check_device(cfg, device)
    _run_pki(lambda: pki_actions.revoke(cfg, device, _emit))


@security_app.command("on")
def security_on() -> None:
    """Broker-blind: AEAD bound to topic/sender/seq/time/epoch + signed commands."""
    cfg = _cfg()
    _run_remote(lambda: actions.set_security(cfg, "on", _emit))


@security_app.command("off")
def security_off() -> None:
    """TLS only: the broker can read and change everything."""
    cfg = _cfg()
    _run_remote(lambda: actions.set_security(cfg, "off", _emit))


@security_app.command("status")
def security_status() -> None:
    """Show the current security mode."""
    cfg = _cfg()
    _emit(f"[demo] security: {actions.security_mode(cfg)}")


@kdc_app.command("status")
def kdc_status() -> None:
    """Current epoch, members and rekey history (never keys)."""
    cfg = _cfg()
    st = _run_remote(lambda: remote.kdc_status(cfg))
    _emit(f"[kdc] epoch {st['epoch']}  members: {', '.join(st['members']) or '-'}")  # type: ignore[index]
    if st["revoked"]:  # type: ignore[index]
        _emit(f"[kdc] revoked: {', '.join(st['revoked'])}")  # type: ignore[index]
    for h in st["history"][-5:]:  # type: ignore[index]
        _emit(
            f"[kdc]   epoch {h['epoch']}: {h['reason']} ({len(h['members'])} members, {h['ms']} ms)"
        )


@kdc_app.command("rekey")
def kdc_rekey() -> None:
    """Force a new epoch."""
    cfg = _cfg()
    st = _run_remote(lambda: remote.kdc_rekey(cfg))
    _emit(f"[kdc] rekeyed → epoch {st['epoch']}")  # type: ignore[index]


@log_app.command("verify")
def log_verify() -> None:
    """Verify tree head, consistency with last run, inclusion of every directory cert."""
    cfg = _cfg()
    if not _run_pki(lambda: pki_actions.log_verify(cfg, _emit)):
        raise typer.Exit(code=1)


@app.command()
def keys() -> None:
    """List what the key directory serves (device, log leaf, fingerprint)."""
    cfg = _cfg()
    _run_pki(lambda: pki_actions.keys_table(cfg, _emit))


@bench_app.command("quick")
def bench_quick() -> None:
    """Run a quick benchmark."""
    _todo(8, "bench quick")


# --- demo / runners -----------------------------------------------------------------------


@demo_app.command("reset")
def demo_reset() -> None:
    """Reset the demo: clear attack rules and captures, reset every device."""
    cfg = _cfg()
    _run_remote(lambda: actions.demo_reset(cfg, _emit))


@device_app.command("run")
def device_run(device: str = typer.Option(..., "--id", help="Device id from home.yaml.")) -> None:
    """Run a simulated device (normally started by docker compose)."""
    from devices.kinds import build

    cfg = _cfg()
    _check_device(cfg, device)
    build(cfg, device).run_forever()


@proxy_app.command("run")
def proxy_run() -> None:
    """Run the evil-broker proxy (normally started by docker compose)."""
    import asyncio

    from evilbroker.proxy import serve

    asyncio.run(serve(_cfg()))


@proxy_app.command("status")
def proxy_status() -> None:
    """Show armed rules and counters."""
    cfg = _cfg()
    st = _run_remote(lambda: remote.proxy_status(cfg))
    _emit(f"[evil-broker] {st}")


@proxy_app.command("clear")
def proxy_clear() -> None:
    """Disarm every attack rule."""
    cfg = _cfg()
    _run_remote(lambda: remote.proxy_clear(cfg))
    _emit("[evil-broker] all rules cleared")


@service_app.command("directory")
def run_directory() -> None:
    """Run the key directory (normally started by docker compose)."""
    from directory.run import serve

    serve(_cfg())


@service_app.command("kdc")
def run_kdc() -> None:
    """Run the KDC (normally started by docker compose)."""
    from kdc.run import serve

    serve(_cfg())


@service_app.command("translog")
def run_translog() -> None:
    """Run the transparency log (normally started by docker compose)."""
    from translog.run import serve

    serve(_cfg())


@dashboard_app.command("run")
def dashboard_run(
    host: str = typer.Option("127.0.0.1", help="Bind address (keep localhost)."),
    port: int = typer.Option(8000, help="Port."),
) -> None:
    """Run the dashboard backend (serves the built frontend too)."""
    import uvicorn

    from dashboard.app import create_app

    uvicorn.run(create_app(_cfg()), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
