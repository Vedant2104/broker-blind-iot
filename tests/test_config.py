from __future__ import annotations

import pytest

from securelib.config import Config, load_config


def test_loads_devices_and_topics(cfg: Config) -> None:
    assert {"front-door", "back-door", "thermostat", "smoke-kitchen", "phone"} <= set(cfg.devices)
    assert "home/door/front/cmd" in cfg.topics
    assert "home/smoke/kitchen" in cfg.topics


def test_identities_include_services(cfg: Config) -> None:
    assert "hub" in cfg.identities
    assert "phone" in cfg.identities


def test_env_overrides_broker(cfg: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BBIOT_BROKER_HOST", "broker")
    monkeypatch.setenv("BBIOT_BROKER_PORT", "18883")
    c = load_config()
    assert (c.broker_host, c.broker_port) == ("broker", 18883)
