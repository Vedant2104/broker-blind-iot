"""HTTP control API for the evil broker. Topics are validated against the
home config allowlist; nothing here executes commands or exposes secrets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from securelib.config import Config

if TYPE_CHECKING:
    from evilbroker.proxy import EvilBroker


class TopicBody(BaseModel):
    topic: str


class RedirectBody(BaseModel):
    from_topic: str
    to_topic: str


class ModifyBody(BaseModel):
    topic: str
    setpoint: float = Field(ge=-50, le=100)


class DeviceBody(BaseModel):
    device: str


class InjectBody(BaseModel):
    capture_id: int


def create_app(cfg: Config, broker: EvilBroker) -> FastAPI:
    app = FastAPI(title="evil-broker control")

    def check(topic: str) -> None:
        if topic not in cfg.topics:
            raise HTTPException(422, f"unknown topic {topic!r}")

    @app.get("/status")
    def status() -> dict:
        return {"rules": broker.rules.as_dict(), "stats": dict(broker.stats)}

    @app.put("/rules/drop")
    def arm_drop(body: TopicBody) -> dict:
        check(body.topic)
        broker.rules.drop.add(body.topic)
        return status()

    @app.put("/rules/redirect")
    def arm_redirect(body: RedirectBody) -> dict:
        check(body.from_topic)
        check(body.to_topic)
        broker.rules.redirect[body.from_topic] = body.to_topic
        return status()

    @app.put("/rules/modify")
    def arm_modify(body: ModifyBody) -> dict:
        check(body.topic)
        broker.rules.modify[body.topic] = body.setpoint
        return status()

    @app.put("/rules/mitm-dh")
    def arm_mitm(body: DeviceBody) -> dict:
        from evilbroker.mitm_dh import DhMitm

        if body.device not in cfg.devices:
            raise HTTPException(422, f"unknown device {body.device!r}")
        broker.rules.mitm[body.device] = DhMitm(body.device)
        return status()

    @app.get("/mitm")
    def mitm_status() -> dict:
        """Which epochs the broker has stolen keys for (never the keys)."""
        broker.collect_loot()
        notes = {d: m.notes for d, m in broker.rules.mitm.items()}
        return {
            "stolen_epochs": {d: sorted(k) for d, k in broker.loot.items()},
            "notes": notes,
        }

    @app.post("/mitm/decrypt")
    def mitm_decrypt() -> dict:
        found = broker.decrypt_with_loot()
        if found is None:
            raise HTTPException(404, "no captured message under a stolen key")
        return found

    @app.delete("/rules")
    def clear_rules() -> dict:
        broker.collect_loot()
        broker.rules.clear()
        return status()

    @app.get("/captures")
    def captures(topic: str | None = None, seq: int | None = None, limit: int = 50) -> list[dict]:
        if topic is not None:
            check(topic)
        found = broker.captures.find(topic=topic, seq=seq)
        return [c.summary() for c in found[-max(1, min(limit, 500)) :]]

    @app.post("/inject")
    def inject(body: InjectBody) -> dict:
        cap = broker.captures.get(body.capture_id)
        if cap is None:
            raise HTTPException(404, f"no capture #{body.capture_id}")
        broker.inject(cap)
        return cap.summary()

    @app.post("/reset")
    def reset() -> dict:
        broker.reset()
        return status()

    return app
