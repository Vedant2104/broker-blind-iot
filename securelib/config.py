"""Load the home config (devices, topics, broker) with environment overrides.

Environment variables:
  BBIOT_CONFIG       path to home.yaml        (default: ./config/home.yaml)
  BBIOT_SECRETS_DIR  where generated keys go  (default: ./secrets)
  BBIOT_BROKER_HOST  override broker.host
  BBIOT_BROKER_PORT  override broker.port
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Device:
    id: str
    kind: str
    label: str
    topics: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    broker_host: str
    broker_port: int
    devices: dict[str, Device]
    services: tuple[str, ...]
    secrets_dir: Path

    @property
    def identities(self) -> list[str]:
        """Every name that gets an mTLS client certificate."""
        return [*self.devices, *self.services]

    @property
    def topics(self) -> list[str]:
        """Every topic a device publishes or listens on (the allowlist)."""
        return sorted({t for d in self.devices.values() for t in d.topics.values()})

    @property
    def tls_dir(self) -> Path:
        return self.secrets_dir / "tls"


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("BBIOT_CONFIG", "config/home.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    broker = raw.get("broker", {})
    devices = {
        dev_id: Device(
            id=dev_id,
            kind=spec["kind"],
            label=spec.get("label", dev_id),
            topics=dict(spec.get("topics") or {}),
        )
        for dev_id, spec in (raw.get("devices") or {}).items()
    }
    return Config(
        broker_host=os.environ.get("BBIOT_BROKER_HOST", broker.get("host", "localhost")),
        broker_port=int(os.environ.get("BBIOT_BROKER_PORT", broker.get("port", 8883))),
        devices=devices,
        services=tuple(raw.get("services") or ()),
        secrets_dir=Path(os.environ.get("BBIOT_SECRETS_DIR", "secrets")),
    )
