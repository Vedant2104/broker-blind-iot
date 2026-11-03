"""Talks to the real Mosquitto from docker compose. Run with `make test-integration`
(or start the broker and set BBIOT_INTEGRATION=1)."""

from __future__ import annotations

import os

import pytest

from cli import doctor
from securelib.config import load_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("BBIOT_INTEGRATION") != "1", reason="broker not running"),
]


def test_roundtrip_with_client_cert() -> None:
    result = doctor.roundtrip(load_config(), "cli")
    assert result.ok, result.detail


def test_broker_refuses_client_without_cert() -> None:
    result = doctor.rejects_without_cert(load_config(), "cli")
    assert result.ok, result.detail
