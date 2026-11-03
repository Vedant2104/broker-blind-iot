"""Load the home config (devices, topics, broker) with environment overrides.

Environment variables:
  BBIOT_CONFIG            path to home.yaml           (default: ./config/home.yaml)
  BBIOT_SECRETS_DIR       where generated keys go     (default: ./secrets)
  BBIOT_BROKER_HOST/PORT  where clients connect (the evil-broker proxy)
  BBIOT_MOSQUITTO_HOST/PORT  the real Mosquitto (used by spy)
  BBIOT_PROXY_HOST/PORT   evil-broker control API
  BBIOT_DEVICE_HOST       host for device control APIs; "service" = use the
                          device id as hostname (inside docker compose)
  BBIOT_DIRECTORY_HOST/PORT, BBIOT_TRANSLOG_HOST/PORT
  BBIOT_OFFLINE_DIR       offline root + admin keys (default: ./offline);
                          never mounted into the running system
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
    log_name: str
    control_port: int
    topics: dict[str, str] = field(default_factory=dict)
    commissioned: bool = True


@dataclass(frozen=True)
class Config:
    broker_host: str
    broker_port: int
    mosquitto_host: str
    mosquitto_port: int
    proxy_host: str
    proxy_port: int
    device_host: str
    devices: dict[str, Device]
    services: tuple[str, ...]
    secrets_dir: Path
    directory_host: str = "localhost"
    directory_port: int = 8443
    translog_host: str = "localhost"
    translog_port: int = 8444
    offline_dir: Path = Path("offline")

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

    @property
    def pki_public_dir(self) -> Path:
        """Root cert, signed admin roster, log cert: public, given to everyone."""
        return self.secrets_dir / "pki" / "public"

    @property
    def translog_key_path(self) -> Path:
        return self.secrets_dir / "translog" / "log.key"

    def device_key_dir(self, device_id: str) -> Path:
        """A device's private identity keys (mounted only into that device)."""
        return self.secrets_dir / "devices" / device_id

    @property
    def state_dir(self) -> Path:
        """Pins and last-seen tree head for the CLI / dashboard."""
        return self.secrets_dir / "state"

    @property
    def directory_url(self) -> str:
        return f"https://{self.directory_host}:{self.directory_port}"

    @property
    def translog_url(self) -> str:
        return f"https://{self.translog_host}:{self.translog_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    def device_url(self, device_id: str) -> str:
        dev = self.devices[device_id]
        host = dev.id if self.device_host == "service" else self.device_host
        return f"http://{host}:{dev.control_port}"

    def device_for_topic(self, topic: str) -> Device | None:
        for dev in self.devices.values():
            if topic in dev.topics.values():
                return dev
        return None


def _env(name: str, default: object) -> str:
    return os.environ.get(name, str(default))


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("BBIOT_CONFIG", "config/home.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    broker = raw.get("broker", {})
    mosq = raw.get("mosquitto", {})
    proxy = raw.get("proxy_control", {})
    directory = raw.get("directory", {})
    translog = raw.get("translog", {})
    devices = {
        dev_id: Device(
            id=dev_id,
            kind=spec["kind"],
            label=spec.get("label", dev_id),
            log_name=spec.get("log_name", dev_id),
            control_port=int(spec.get("control_port", 0)),
            topics=dict(spec.get("topics") or {}),
            commissioned=bool(spec.get("commissioned", True)),
        )
        for dev_id, spec in (raw.get("devices") or {}).items()
    }
    return Config(
        broker_host=_env("BBIOT_BROKER_HOST", broker.get("host", "localhost")),
        broker_port=int(_env("BBIOT_BROKER_PORT", broker.get("port", 8883))),
        mosquitto_host=_env("BBIOT_MOSQUITTO_HOST", mosq.get("host", "localhost")),
        mosquitto_port=int(_env("BBIOT_MOSQUITTO_PORT", mosq.get("port", 8884))),
        proxy_host=_env("BBIOT_PROXY_HOST", proxy.get("host", "localhost")),
        proxy_port=int(_env("BBIOT_PROXY_PORT", proxy.get("port", 8090))),
        device_host=_env("BBIOT_DEVICE_HOST", "127.0.0.1"),
        devices=devices,
        services=tuple(raw.get("services") or ()),
        secrets_dir=Path(_env("BBIOT_SECRETS_DIR", "secrets")),
        directory_host=_env("BBIOT_DIRECTORY_HOST", directory.get("host", "localhost")),
        directory_port=int(_env("BBIOT_DIRECTORY_PORT", directory.get("port", 8443))),
        translog_host=_env("BBIOT_TRANSLOG_HOST", translog.get("host", "localhost")),
        translog_port=int(_env("BBIOT_TRANSLOG_PORT", translog.get("port", 8444))),
        offline_dir=Path(_env("BBIOT_OFFLINE_DIR", "offline")),
    )
