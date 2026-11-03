"""The simulated devices: door lock, thermostat, smoke sensor, phone app."""

from __future__ import annotations

import time
from typing import Any

from devices.base import DeviceBase
from securelib.config import Config


class Lock(DeviceBase):
    kind = "lock"

    def reset_state(self) -> None:
        self.locked = True
        self.last_by: str | None = None

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        cmd = body.get("cmd")
        if cmd not in ("lock", "unlock"):
            self.log.info(f"ignored unknown cmd={cmd!r} from={sender}")
            return
        self.locked = cmd == "lock"
        self.last_by = sender
        self.log.info(
            f"✓ accepted cmd={cmd} from={sender} seq={seq} → "
            f"{'LOCKED' if self.locked else 'UNLOCKED'}"
        )
        self.publish_state()

    def state(self) -> dict[str, Any]:
        return {"locked": self.locked, "by": self.last_by}


class Thermostat(DeviceBase):
    kind = "thermostat"

    def reset_state(self) -> None:
        self.setpoint = 21.0
        self.temperature = 20.5
        self._last_report = 0.0

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        if body.get("cmd") != "set" or not isinstance(body.get("setpoint"), int | float):
            self.log.info(f"ignored cmd={body.get('cmd')!r} from={sender}")
            return
        self.setpoint = float(body["setpoint"])
        self.log.info(f"✓ accepted cmd=set from={sender} seq={seq} → setpoint {self.setpoint}°C")
        self.publish_state()

    def tick(self) -> None:
        # Drift 0.1°C per second toward the setpoint; report every 10 s.
        diff = self.setpoint - self.temperature
        if abs(diff) > 0.05:
            self.temperature = round(self.temperature + max(-0.1, min(0.1, diff)), 2)
        if time.time() - self._last_report >= 10:
            self._last_report = time.time()
            self.publish_state()

    def state(self) -> dict[str, Any]:
        return {"setpoint": self.setpoint, "temperature": self.temperature}


class SmokeSensor(DeviceBase):
    kind = "smoke"
    ALARM_SECONDS = 8

    def reset_state(self) -> None:
        self.alarm_until = 0.0

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        if body.get("cmd") != "test":
            self.log.info(f"ignored cmd={body.get('cmd')!r} from={sender}")
            return
        self.log.info(f"✓ accepted cmd=test from={sender} seq={seq} → raising test alarm")
        self.raise_alarm(test=True)

    def raise_alarm(self, *, test: bool) -> None:
        self.alarm_until = time.time() + self.ALARM_SECONDS
        self.publish(self.dev.topics["alarm"], {"alarm": "smoke", "test": test})
        self.log.info(f"🔥 ALARM published on {self.dev.topics['alarm']}")
        self.publish_state()

    def tick(self) -> None:
        if self.alarm_until and time.time() >= self.alarm_until:
            self.alarm_until = 0.0
            self.publish_state()

    def state(self) -> dict[str, Any]:
        return {"alarm": bool(self.alarm_until)}


class Phone(DeviceBase):
    """The phone app: sends commands, watches every state topic and alarms."""

    kind = "app"

    def reset_state(self) -> None:
        self.alarms: list[dict[str, Any]] = []
        self.seen: dict[str, dict[str, Any]] = {}

    def subscriptions(self) -> list[str]:
        topics = []
        for dev in self.cfg.devices.values():
            topics += [t for name, t in dev.topics.items() if name in ("state", "alarm")]
        return topics

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        alarm_topics = {d.topics.get("alarm") for d in self.cfg.devices.values()}
        if topic in alarm_topics:
            self.alarms.append({"ts": time.time(), "topic": topic, "from": sender, **body})
            self.log.info(f"🔔 ALARM received from={sender} on {topic}: {body}")
        else:
            self.seen[topic] = body

    def state(self) -> dict[str, Any]:
        return {"alarms_received": len(self.alarms)}


KINDS: dict[str, type[DeviceBase]] = {
    "lock": Lock,
    "thermostat": Thermostat,
    "smoke": SmokeSensor,
    "app": Phone,
}


def build(cfg: Config, device_id: str, mode: str = "off") -> DeviceBase:
    dev = cfg.devices[device_id]
    return KINDS[dev.kind](cfg, dev, mode=mode)
