"""Run the KDC: MQTT client (through the untrusted broker) + small control API."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from kdc.service import Kdc, log
from securelib.config import Config
from securelib.identity import read_private
from securelib.mqtt import make_client
from securelib.trust import PeerVerifier
from translog.run import wait_for

IDENTITY = "kdc"


class DeviceBody(BaseModel):
    device: str


def create_app(cfg: Config, kdc: Kdc) -> FastAPI:
    app = FastAPI(title="bbiot KDC")

    @app.get("/status")
    def status() -> dict:
        return kdc.status()

    @app.post("/rekey")
    def rekey() -> dict:
        kdc.rekey("operator request")
        return kdc.status()

    @app.post("/allow-unsigned")
    def allow_unsigned(body: DeviceBody) -> dict:
        """Attack 6 demo only: accept ONE unsigned key exchange from this device."""
        if body.device not in cfg.devices:
            raise HTTPException(422, "unknown device")
        kdc.allow_unsigned.add(body.device)
        log.info(f"⚠ demo: will accept one UNSIGNED key exchange from {body.device}")
        return kdc.status()

    return app


def serve(cfg: Config) -> None:
    key_path = cfg.secrets_dir / "kdc" / "kdc.key"
    wait_for(key_path, "the KDC signing key")
    wait_for(cfg.pki_public_dir / "kdc.crt", "the KDC certificate")
    data = Path(os.environ.get("BBIOT_DATA_DIR", "data")) / "kdc"
    verifier = PeerVerifier.for_identity(cfg, IDENTITY, data / "trust")

    client = make_client(cfg, IDENTITY)

    def publish(topic: str, msg: dict, retain: bool = False) -> None:
        client.publish(topic, json.dumps(msg, separators=(",", ":")), qos=1, retain=retain)

    kdc = Kdc(read_private(key_path), verifier, publish, data / "epoch")

    def on_connect(c, _u, _f, rc, _p) -> None:
        if rc.is_failure:
            log.info(f"broker refused connection: {rc}")
            return
        c.subscribe("kdc/join/+", qos=1)
        log.info(f"connected to broker {cfg.broker_host}:{cfg.broker_port} (mTLS as 'kdc')")
        kdc.announce()

    client.on_connect = on_connect
    client.on_message = lambda _c, _u, m: kdc.on_message(m.topic, m.payload)
    client.reconnect_delay_set(1, 5)
    client.connect_async(cfg.broker_host, cfg.broker_port, keepalive=20)
    client.loop_start()
    threading.Thread(target=kdc.loop, daemon=True, name="kdc-loop").start()

    host = os.environ.get("BBIOT_LISTEN", "127.0.0.1")
    port = int(os.environ.get("BBIOT_KDC_PORT", "8095"))
    log.info(f"control API on {host}:{port} (status shows epochs and members, never keys)")
    uvicorn.run(create_app(cfg, kdc), host=host, port=port, log_level="warning")
