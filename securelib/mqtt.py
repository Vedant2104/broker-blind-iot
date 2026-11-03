"""mTLS MQTT client helper (paho-mqtt v2)."""

from __future__ import annotations

import ssl
import uuid
from typing import Literal

import paho.mqtt.client as mqtt

from securelib.config import Config
from securelib.tls import client_paths

Target = Literal["broker", "mosquitto"]


def tls_context(cfg: Config, identity: str, *, client_cert: bool = True) -> ssl.SSLContext:
    """TLS context that verifies the broker and (optionally) presents a client cert."""
    paths = client_paths(cfg.tls_dir, identity)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(paths.ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert:
        ctx.load_cert_chain(certfile=str(paths.cert), keyfile=str(paths.key))
    return ctx


def make_client(cfg: Config, identity: str, *, client_cert: bool = True) -> mqtt.Client:
    """Build a paho client that connects with this identity's client certificate.

    ``client_cert=False`` connects with server verification only — used to show
    that the broker rejects clients without a certificate.
    """
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"{identity}-{uuid.uuid4().hex[:8]}",
    )
    client.tls_set_context(tls_context(cfg, identity, client_cert=client_cert))
    return client


def address(cfg: Config, target: Target = "broker") -> tuple[str, int]:
    """Where to connect: the broker clients use (evil proxy) or Mosquitto itself."""
    if target == "mosquitto":
        return cfg.mosquitto_host, cfg.mosquitto_port
    return cfg.broker_host, cfg.broker_port
