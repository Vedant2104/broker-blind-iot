"""Liveness monitor: the broker can drop messages; the hub detects it.

Signals (security ON — sequence numbers are in every sealed header, in clear but
authenticated, so the broker can't fake them):

  * sequence gaps — the hub sees everything a device publishes; a missing seq
    that doesn't show up within a grace period was dropped
  * missing heartbeats — critical devices send a signed heartbeat every few seconds
  * unacked alarms — the smoke sensor reports alarms nobody acknowledged
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

RESTART_JUMP = 500  # a bigger jump is a device restart (seq blocks reserved on disk)


@dataclass
class SenderState:
    highest: int = 0
    highest_ts_ms: int = 0
    missing: dict[int, tuple[float, int, int]] = field(
        default_factory=dict
    )  # seq -> (noticed, lo_ts, hi_ts)
    last_hb: float | None = None
    hb_late: bool = False
    dropped: int = 0
    reported_alarms: set[int] = field(default_factory=set)


class Monitor:
    def __init__(
        self,
        *,
        heartbeat_interval: float = 5.0,
        grace: float = 2.0,
        now: Callable[[], float] = time.monotonic,
        wall_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        self.hb_interval = heartbeat_interval
        self.grace = grace
        self.now = now
        self.wall_ms = wall_ms
        self.senders: dict[str, SenderState] = {}
        self.expect_heartbeats: set[str] = set()

    def _state(self, sender: str) -> SenderState:
        return self.senders.setdefault(sender, SenderState())

    # --- inputs ---------------------------------------------------------------------------

    def on_message(self, sender: str, seq: int, ts_ms: int) -> list[dict[str, Any]]:
        st = self._state(sender)
        alerts: list[dict[str, Any]] = []
        if seq in st.missing:  # arrived late / reordered: not a drop
            del st.missing[seq]
        if st.highest and seq > st.highest + 1:
            if seq - st.highest > RESTART_JUMP:
                alerts.append(_alert("info", f"{sender} restarted (seq {st.highest} → {seq})"))
                st.missing.clear()
            else:
                noticed = self.now()
                for s in range(st.highest + 1, seq):
                    st.missing[s] = (noticed, st.highest_ts_ms, ts_ms)
        if seq > st.highest:
            st.highest, st.highest_ts_ms = seq, ts_ms
        return alerts

    def on_heartbeat(self, sender: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        st = self._state(sender)
        alerts = []
        if st.hb_late:
            alerts.append(_alert("info", f"heartbeat from {sender} is back"))
        st.last_hb, st.hb_late = self.now(), False
        for alarm in body.get("unacked_alarms", []):
            seq = int(alarm.get("seq", 0))
            if seq in st.reported_alarms:
                continue
            st.reported_alarms.add(seq)
            ttd = (self.wall_ms() - int(alarm.get("ts_ms", self.wall_ms()))) / 1000
            alerts.append(
                _alert(
                    "critical",
                    f"ALARM DROPPED: {sender} raised an alarm (seq {seq}) that nobody "
                    "acknowledged — the broker is suppressing it",
                    sender=sender,
                    seq=seq,
                    detect_s=round(ttd, 2),
                    check="end-to-end ack",
                )
            )
        return alerts

    def tick(self) -> list[dict[str, Any]]:
        now = self.now()
        alerts = []
        for sender, st in self.senders.items():
            due = sorted(
                s for s, (noticed, _, _) in st.missing.items() if now - noticed >= self.grace
            )
            if due:
                lo_ts = min(st.missing[s][1] for s in due)
                st.dropped += len(due)
                for s in due:
                    del st.missing[s]
                alerts.append(
                    _alert(
                        "critical",
                        f"DROPPED: {len(due)} message(s) from {sender} never arrived "
                        f"(seq {_ranges(due)})",
                        sender=sender,
                        seq=_ranges(due),
                        check="sequence gap",
                        detect_s=round((self.wall_ms() - lo_ts) / 1000, 2) if lo_ts else None,
                    )
                )
        for sender in sorted(self.expect_heartbeats):
            st = self._state(sender)
            if st.last_hb is None or st.hb_late:
                continue
            silent = now - st.last_hb
            if silent > 3 * self.hb_interval:
                st.hb_late = True
                alerts.append(
                    _alert(
                        "critical",
                        f"MISSING HEARTBEAT: nothing from {sender} for {silent:.0f}s "
                        "(offline, or the broker is dropping its traffic)",
                        sender=sender,
                        check="heartbeat",
                        detect_s=round(silent, 1),
                    )
                )
        return alerts

    def status(self) -> dict[str, dict[str, Any]]:
        now = self.now()
        return {
            s: {
                "highest_seq": st.highest,
                "dropped": st.dropped,
                "heartbeat_age": None if st.last_hb is None else round(now - st.last_hb, 1),
                "heartbeat_late": st.hb_late,
            }
            for s, st in self.senders.items()
        }


def _alert(severity: str, title: str, **details: Any) -> dict[str, Any]:
    return {"severity": severity, "title": title, **details}


def _ranges(seqs: list[int]) -> str:
    out, start, prev = [], seqs[0], seqs[0]
    for s in seqs[1:]:
        if s == prev + 1:
            prev = s
            continue
        out.append(f"{start}" if start == prev else f"{start}–{prev}")
        start = prev = s
    out.append(f"{start}" if start == prev else f"{start}–{prev}")
    return ", ".join(out)
