"""bbiot — every action in the system is a command here.

Phase 0: `tls init` and `doctor` work. Other commands are wired with their
final arguments (validated against config/home.yaml) and say which phase
implements them.
"""

from __future__ import annotations

import os
from enum import StrEnum

import typer

from cli import doctor as doctor_mod
from securelib.config import Config, load_config
from securelib.log import get_logger
from securelib.tls import init_tls, tls_material_exists

app = typer.Typer(help="Broker-Blind IoT command line.", no_args_is_help=True)
tls_app = typer.Typer(help="Transport TLS (mTLS) material for the broker.", no_args_is_help=True)
attack_app = typer.Typer(help="Run an attack through the evil-broker proxy.", no_args_is_help=True)
admin_app = typer.Typer(help="Admin approvals (2-of-3 signatures).", no_args_is_help=True)
log_app = typer.Typer(help="Transparency log.", no_args_is_help=True)
bench_app = typer.Typer(help="Benchmarks.", no_args_is_help=True)
demo_app = typer.Typer(help="Demo helpers.", no_args_is_help=True)

app.add_typer(tls_app, name="tls")
app.add_typer(attack_app, name="attack")
app.add_typer(admin_app, name="admin")
app.add_typer(log_app, name="log")
app.add_typer(bench_app, name="bench")
app.add_typer(demo_app, name="demo")

log = get_logger("cli")


class Admin(StrEnum):
    A = "A"
    B = "B"
    C = "C"


def _cfg() -> Config:
    return load_config()


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


# --- working in phase 0 -----------------------------------------------------


@tls_app.command("init")
def tls_init(
    force: bool = typer.Option(False, "--force", help="Regenerate everything, including the CA."),
    if_missing: bool = typer.Option(False, "--if-missing", help="Do nothing if a CA exists."),
) -> None:
    """Create the transport CA, broker cert and one client cert per device/service."""
    cfg = _cfg()
    if if_missing and tls_material_exists(cfg.tls_dir) and not force:
        log.info(f"TLS material already present in {cfg.tls_dir}, keeping it")
        return
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


# --- wired, implemented in later phases --------------------------------------


@app.command()
def send(
    device: str = typer.Option(..., help="Sending device, e.g. phone."),
    topic: str = typer.Option(..., help="Topic, e.g. home/door/front/cmd."),
    cmd: str = typer.Option(..., help="Command, e.g. unlock."),
) -> None:
    """Send a device command."""
    cfg = _cfg()
    _check_device(cfg, device)
    _check_topic(cfg, topic)
    _todo(1, "send")


@app.command()
def spy(topic: str = typer.Option("home/#", help="Topic filter.")) -> None:
    """Show what the broker sees."""
    _check_topic(_cfg(), topic, allow_wildcard=True)
    _todo(1, "spy")


@attack_app.command("read")
def attack_read() -> None:
    """1. Broker reads payloads."""
    _todo(1, "attack read")


@attack_app.command("modify")
def attack_modify(
    setpoint: float = typer.Option(30.0, help="Setpoint the broker injects."),
) -> None:
    """2. Broker modifies a thermostat setpoint."""
    _todo(1, "attack modify")


@attack_app.command("replay")
def attack_replay(
    seq: int = typer.Option(..., help="Sequence number of the captured message."),
) -> None:
    """3. Broker replays a captured 'unlock front door'."""
    _todo(1, "attack replay")


@attack_app.command("redirect")
def attack_redirect(
    from_topic: str = typer.Option(..., "--from", help="Original topic."),
    to_topic: str = typer.Option(..., "--to", help="Topic to redirect to."),
) -> None:
    """4. Broker redirects a command to another device's topic."""
    cfg = _cfg()
    _check_topic(cfg, from_topic)
    _check_topic(cfg, to_topic)
    _todo(1, "attack redirect")


@attack_app.command("drop")
def attack_drop(topic: str = typer.Option(..., help="Topic whose messages are dropped.")) -> None:
    """5. Broker silently drops messages (e.g. the smoke alarm)."""
    _check_topic(_cfg(), topic)
    _todo(1, "attack drop")


@attack_app.command("mitm-dh")
def attack_mitm_dh() -> None:
    """6. Broker MITMs an unsigned key exchange."""
    _todo(4, "attack mitm-dh")


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


@app.command()
def pair(device: str = typer.Option(..., help="New device id, e.g. garage-lock.")) -> None:
    """Pair a new device (needs 2-of-3 admin approvals)."""
    _todo(2, "pair")


@admin_app.command("approve")
def admin_approve(
    admin: Admin = typer.Option(..., help="Approving admin."),
    action: str = typer.Option(..., help="Pending action id."),
) -> None:
    """Sign a pending admin action."""
    _todo(2, "admin approve")


@log_app.command("verify")
def log_verify() -> None:
    """Verify transparency-log consistency and inclusion proofs."""
    _todo(2, "log verify")


@bench_app.command("quick")
def bench_quick() -> None:
    """Run a quick benchmark."""
    _todo(8, "bench quick")


@demo_app.command("reset")
def demo_reset() -> None:
    """Reset the demo to a clean state."""
    _todo(1, "demo reset")


if __name__ == "__main__":
    app()
