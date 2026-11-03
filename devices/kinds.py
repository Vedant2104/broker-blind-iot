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

    ACK_TIMEOUT = 2.0
    RETRIES = 2

    def reset_state(self) -> None:
        self.alarm_until = 0.0
        self.pending_alarms: list[dict[str, Any]] = []  # sent, waiting for the hub's ack

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        if body.get("cmd") != "test":
            self.log.info(f"ignored cmd={body.get('cmd')!r} from={sender}")
            return
        self.log.info(f"✓ accepted cmd=test from={sender} seq={seq} → raising test alarm")
        self.raise_alarm(test=True)

    def raise_alarm(self, *, test: bool, attempt: int = 1, first_ts: int | None = None) -> None:
        self.alarm_until = time.time() + self.ALARM_SECONDS
        self.publish(self.dev.topics["alarm"], {"alarm": "smoke", "test": test})
        self.log.info(f"🔥 ALARM published on {self.dev.topics['alarm']} (attempt {attempt})")
        if self.channel.mode == "on":
            self.pending_alarms.append(
                {
                    "seq": self.channel.last_seq,
                    "ts_ms": first_ts or int(time.time() * 1000),
                    "sent": time.monotonic(),
                    "attempt": attempt,
                    "test": test,
                }
            )
        self.publish_state()

    def on_ack(self, acker: str, body: dict[str, Any]) -> None:
        if acker != "hub":
            return
        seq = body.get("for_seq")
        before = len(self.pending_alarms)
        self.pending_alarms = [a for a in self.pending_alarms if a["seq"] != seq]
        if len(self.pending_alarms) < before:
            self.log.info(f"✓ hub acknowledged alarm (seq {seq})")

    REPORT_SECONDS = 60  # keep reporting an unacked alarm in heartbeats this long

    def unacked_alarms(self) -> list[dict[str, Any]]:
        cutoff = int(time.time() * 1000) - self.REPORT_SECONDS * 1000
        self.pending_alarms = [a for a in self.pending_alarms if a["ts_ms"] >= cutoff]
        return [
            {"seq": a["seq"], "ts_ms": a["ts_ms"]}
            for a in self.pending_alarms
            if a["attempt"] > self.RETRIES
        ]

    def tick(self) -> None:
        if self.alarm_until and time.time() >= self.alarm_until:
            self.alarm_until = 0.0
            self.publish_state()
        now = time.monotonic()
        for a in list(self.pending_alarms):
            if a["attempt"] > self.RETRIES or now - a["sent"] < self.ACK_TIMEOUT:
                continue
            if a["attempt"] == self.RETRIES:  # give up re-sending; heartbeats will report it
                a["attempt"] += 1
                self.log.info(f"✗ alarm (seq {a['seq']}) never acknowledged by the hub")
                self.alert(
                    "critical",
                    "Alarm not acknowledged",
                    "the hub never confirmed the smoke alarm",
                    check="end-to-end ack",
                )
                continue
            self.pending_alarms.remove(a)
            self.log.info(f"no ack for alarm seq {a['seq']} — re-sending")
            self.raise_alarm(test=a["test"], attempt=a["attempt"] + 1, first_ts=a["ts_ms"])

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


def build(cfg: Config, device_id: str, mode: str | None = None) -> DeviceBase:
    dev = cfg.devices[device_id]
    if dev.kind == "hub":
        from hub.hub import Hub

        return Hub(cfg, dev, mode=mode)
    return KINDS[dev.kind](cfg, dev, mode=mode)
