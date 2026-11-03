from __future__ import annotations

from typer.testing import CliRunner

from cli.main import app
from securelib.config import Config

runner = CliRunner()


def test_help_lists_commands(cfg: Config) -> None:
    out = runner.invoke(app, ["--help"]).output
    for cmd in ("send", "spy", "attack", "pair", "admin", "log", "bench", "demo", "tls", "doctor"):
        assert cmd in out


def test_attack_help_lists_all_ten(cfg: Config) -> None:
    out = runner.invoke(app, ["attack", "--help"]).output
    for name in (
        "read",
        "modify",
        "replay",
        "redirect",
        "drop",
        "mitm-dh",
        "compromised-device",
        "counterfeit",
        "swap-key",
        "kdc-vs-directory",
    ):
        assert name in out


def test_tls_init_writes_certs(cfg: Config) -> None:
    result = runner.invoke(app, ["tls", "init"])
    assert result.exit_code == 0, result.output
    assert (cfg.tls_dir / "ca.crt").exists()
    assert (cfg.tls_dir / "clients" / "phone.crt").exists()
    # Never print private key material.
    assert "PRIVATE KEY" not in result.output


def test_tls_init_if_missing_is_noop(cfg: Config) -> None:
    runner.invoke(app, ["tls", "init"])
    result = runner.invoke(app, ["tls", "init", "--if-missing"])
    assert result.exit_code == 0
    assert "keeping it" in result.output


def test_send_rejects_unknown_device(cfg: Config) -> None:
    result = runner.invoke(
        app, ["send", "--device", "toaster", "--topic", "home/door/front/cmd", "--cmd", "unlock"]
    )
    assert result.exit_code == 2
    assert "unknown device" in result.output


def test_send_rejects_unknown_topic(cfg: Config) -> None:
    result = runner.invoke(
        app, ["send", "--device", "phone", "--topic", "home/../etc", "--cmd", "unlock"]
    )
    assert result.exit_code == 2
    assert "unknown topic" in result.output


def test_unimplemented_command_says_which_phase(cfg: Config) -> None:
    result = runner.invoke(app, ["attack", "replay", "--seq", "43"])
    assert result.exit_code == 2
    assert "phase 1" in result.output
