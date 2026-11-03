from __future__ import annotations

from pathlib import Path

import pytest

from securelib.config import Config, load_config

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    """Real home config, with secrets redirected to a temp dir."""
    monkeypatch.setenv("BBIOT_CONFIG", str(REPO / "config" / "home.yaml"))
    monkeypatch.setenv("BBIOT_SECRETS_DIR", str(tmp_path / "secrets"))
    return load_config()
