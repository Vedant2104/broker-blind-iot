"""Device-side liveness and policy (security ON only — with security OFF none of
this is authenticated, so it would prove nothing):

  * signed heartbeats on hb/<id> every few seconds (the hub expects them)
  * end-to-end signed acks: a device acks every command it executes on ack/<id>;
    the sender raises an alert if the ack doesn't come back in time
  * command authorization from the device's MUD profile (`accept_commands_from`)
  * quarantine notices from the hub (signed, versioned)
  * a demo hook to make this device "compromised" (attack 7)
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hub.policy import PolicyStore
from hub.quarantine import TOPIC as QUARANTINE_TOPIC
from hub.quarantine import NoticeTracker
from securelib.channel import NoGroupKey
from securelib.message import SUITES, decrypt_unchecked, peek_header
from securelib.pki import TrustError

if TYPE_CHECKING:
    from devices.base import DeviceBase

HEARTBEAT_SECONDS = 5.0
ACK_TIMEOUT = 3.0


class Liveness:
    def __init__(self, device: DeviceBase) -> None:
        self.d = device
        self.hb_n = 0
        self.last_hb = 0.0
        self.pending: dict[int, dict[str, Any]] = {}  # my seq -> command awaiting an ack
        self.quarantine = NoticeTracker()
        self.compromised: list[str] = []
        self.spied = 0
        mud = Path(os.environ.get("BBIOT_MUD_DIR", "config/mud"))
        self.profile = PolicyStore(mud).get(device.dev.id) if mud.is_dir() else None

    @property
    def on(self) -> bool:
        return self.d.channel.mode == "on"

    def subscriptions(self) -> list[str]:
        subs = [QUARANTINE_TOPIC]
        if self.d.kind in ("app", "hub"):
            subs.append("ack/+")
        if self.d.kind == "smoke":
            subs.append("ack/hub")
        return subs

    # --- heartbeats + ack timeouts -----------------------------------------------------------

    def tick(self) -> None:
        if not self.on or not self.d.connected:
            return
        now = time.monotonic()
        if self.d.kind != "hub" and now - self.last_hb >= HEARTBEAT_SECONDS:
            self.last_hb = now
            self.hb_n += 1
            body = {"n": self.hb_n, "unacked_alarms": self.d.unacked_alarms()}
            with contextlib.suppress(NoGroupKey):
                self.d.publish(f"hb/{self.d.dev.id}", body, quiet=True)
        for seq, p in list(self.pending.items()):
            if now - p["t0"] > ACK_TIMEOUT:
                del self.pending[seq]
                reason = (
                    f"{p['device']} never confirmed '{p['cmd']}' (seq {seq}) within "
                    f"{ACK_TIMEOUT:g}s — dropped by the broker or not executed"
                )
                self.d.log.info(f"✗ NO ACK: {reason}")
                self.d.alert(
                    "critical",
                    f"No ack from {p['device']}",
                    reason,
                    seq=seq,
                    check="end-to-end ack",
                    detect_s=ACK_TIMEOUT,
                )

    # --- acks --------------------------------------------------------------------------------

    def on_sent_command(self, topic: str, cmd: str, seq: int | None) -> None:
        dev = self.d.cfg.device_for_topic(topic)
        if self.on and seq is not None and dev is not None:
            self.pending[seq] = {
                "device": dev.id,
                "cmd": cmd,
                "topic": topic,
                "t0": time.monotonic(),
            }

    def send_ack(self, topic: str, sender: str | None, seq: int | None, cmd: Any) -> None:
        if not self.on or sender is None or seq is None:
            return
        body = {"for": sender, "for_seq": seq, "topic": topic, "cmd": cmd, "ok": True}
        with contextlib.suppress(NoGroupKey):
            self.d.publish(f"ack/{self.d.dev.id}", body, quiet=True)

    def on_ack(self, acker: str, body: dict[str, Any]) -> None:
        if body.get("for") != self.d.dev.id:
            return
        p = self.pending.pop(int(body.get("for_seq", -1)), None)
        if p is not None and p["device"] == acker:
            rtt = (time.monotonic() - p["t0"]) * 1000
            self.d.log.info(f"✓ signed ack from {acker} for '{p['cmd']}' in {rtt:.0f} ms")
            self.d.events.add("ack", device=acker, cmd=p["cmd"], rtt_ms=round(rtt, 1))
        self.d.on_ack(acker, body)

    # --- authorization -----------------------------------------------------------------------

    def unauthorized(self, topic: str, sender: str | None) -> str | None:
        """Commands are accepted only from senders the MUD profile allows."""
        if not self.on or self.profile is None or topic != self.d.dev.topics.get("cmd"):
            return None
        if sender is not None and self.profile.accepts_command_from(sender):
            return None
        return f"unauthorized sender {sender!r} (not allowed by {self.d.dev.id}'s MUD profile)"

    # --- quarantine --------------------------------------------------------------------------

    def on_quarantine_notice(self, payload: bytes) -> None:
        try:
            signed = json.loads(payload)
            changed = self.quarantine.offer(signed, self.d.trust.peer_key("hub"))
        except (ValueError, TrustError) as exc:
            self.d.log.info(f"✗ quarantine notice refused: {exc}")
            return
        if changed:
            q = self.quarantine.quarantined
            self.d.log.info(
                f"hub quarantine list v{self.quarantine.version}: {sorted(q) or 'empty'}"
            )
            self.d.trust.set_quarantined(q)

    # --- attack 7 demo hook ------------------------------------------------------------------

    def compromise(self, topics: list[str]) -> None:
        self.compromised = list(topics)
        self.spied = 0
        self.d.log.info(f"☠ COMPROMISED: subscribing to {', '.join(topics)} (outside my profile)")
        if self.d.client is not None:
            for t in topics:
                self.d.client.subscribe(t, qos=1)

    def is_spied(self, topic: str) -> bool:
        return topic in self.compromised

    def try_decrypt(self, topic: str, payload: bytes) -> dict[str, Any]:
        """Can this device read a sealed message with whatever keys it holds?"""
        h = peek_header(payload)
        if h is None or h.suite not in SUITES:
            return {"ok": False, "reason": "not a sealed message"}
        keys = []
        for g in self.d.channel.groups.values():
            cur = g.current()
            if cur is not None:
                keys.append(cur)
        for epoch, key in keys:
            try:
                decrypt_unchecked(topic, payload, key)
                return {"ok": True, "epoch": epoch}
            except Exception:  # noqa: BLE001,S112 - try the next key
                continue
        held = ", ".join(str(e) for e, _ in keys) or "none"
        return {
            "ok": False,
            "reason": f"message is epoch {h.epoch}; this device only holds epoch(s) {held}",
        }
