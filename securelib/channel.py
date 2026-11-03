"""Message layer between application bodies and MQTT payloads.

Every device publishes through ``Channel.seal`` and reads through ``Channel.open``.
Phase 1 implements only ``mode="off"``: the body is plaintext JSON with an
unauthenticated envelope (sender, seq, ts) — exactly what the broker can read,
change and replay. Phase 3 adds ``mode="on"`` (AEAD bound to topic, sender,
seq, timestamp and epoch) behind the same interface.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from securelib.log import get_logger

MODES = ("off",)


@dataclass
class Opened:
    ok: bool
    body: dict[str, Any] = field(default_factory=dict)
    sender: str | None = None
    seq: int | None = None
    reason: str | None = None


class Channel:
    def __init__(self, identity: str, mode: str = "off") -> None:
        if mode not in MODES:
            raise ValueError(f"unsupported security mode {mode!r} (have: {', '.join(MODES)})")
        self.identity = identity
        self.mode = mode
        self._seq = itertools.count(1)
        self._lock = threading.Lock()
        self.log = get_logger("securelib")

    def next_seq(self) -> int:
        with self._lock:
            return next(self._seq)

    def seal(self, topic: str, body: dict[str, Any]) -> bytes:
        """Wrap an application body for publishing on ``topic``."""
        seq = self.next_seq()
        envelope = {"from": self.identity, "seq": seq, "ts": round(time.time(), 3), **body}
        payload = json.dumps(envelope, separators=(",", ":")).encode()
        self.log.info(
            f"mode=off seq={seq} published {len(payload)} bytes on {topic} "
            f"(plaintext, no protection)"
        )
        return payload

    def open(self, topic: str, payload: bytes) -> Opened:
        """Unwrap a received payload. In mode=off nothing is verified."""
        try:
            envelope = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Opened(ok=False, reason="malformed (not JSON)")
        if not isinstance(envelope, dict):
            return Opened(ok=False, reason="malformed (not an object)")
        sender = envelope.pop("from", None)
        seq = envelope.pop("seq", None)
        envelope.pop("ts", None)
        return Opened(ok=True, body=envelope, sender=sender, seq=seq)
