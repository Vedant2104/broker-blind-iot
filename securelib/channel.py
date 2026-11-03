"""Message layer between application bodies and MQTT payloads.

Every device publishes through ``Channel.seal`` and reads through ``Channel.open``.

  mode="off"  plaintext JSON with an unauthenticated envelope (sender, seq, ts):
              exactly what the broker can read, change and replay (TLS only).
  mode="on"   sealed messages (securelib.message): AEAD under the group key, AAD
              binding topic, sender, seq, timestamp and epoch; sliding replay
              window; Ed25519 sender signature on commands and alarms.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securelib.groupkeys import GroupKeys
from securelib.log import get_logger
from securelib.message import Opener, Reject, seal

MODES = ("off", "on")


class NoGroupKey(RuntimeError):
    pass


@dataclass
class Opened:
    ok: bool
    body: dict[str, Any] = field(default_factory=dict)
    sender: str | None = None
    seq: int | None = None
    reason: str | None = None
    epoch: int | None = None
    signed: bool = False


class SeqCounter:
    """Monotonic sequence numbers that survive restarts: reserves blocks on disk,
    so a rebooted device never reuses a seq (which receivers would call a replay)."""

    BLOCK = 1000

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        start = 1
        if path and path.exists():
            try:
                start = int(path.read_text().strip())
            except ValueError:
                start = 1
        self._next = start
        self._reserved = start
        self._reserve()

    def _reserve(self) -> None:
        self._reserved = self._next + self.BLOCK
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(str(self._reserved))

    def next(self) -> int:
        with self._lock:
            seq = self._next
            self._next += 1
            if self._next >= self._reserved:
                self._reserve()
            return seq


class Channel:
    def __init__(
        self,
        identity: str,
        mode: str = "off",
        *,
        group: GroupKeys | None = None,
        groups: dict[str, GroupKeys] | None = None,
        keymode: str | None = None,
        signer: Ed25519PrivateKey | None = None,
        peer_key: Callable[[str], Ed25519PublicKey | None] = lambda _s: None,
        requires_signature: Callable[[str], bool] = lambda _t: False,
        seq_path: Path | None = None,
        suite: str = "AES-GCM",
    ) -> None:
        self.identity = identity
        self.mode = mode
        self.groups: dict[str, GroupKeys] = dict(groups or {})
        if group is not None:
            self.groups[group.mode] = group
        self.keymode = keymode or (next(iter(self.groups)) if self.groups else "centralized")
        self.signer = signer
        self.requires_signature = requires_signature
        self.suite = suite
        self.seq = SeqCounter(seq_path)
        self.log = get_logger("securelib")
        self.opener = Opener(
            current_key=self._current_key,
            sender_key=peer_key,
            requires_signature=requires_signature,
        )

    @property
    def group(self) -> GroupKeys | None:
        """The active group-key backend (centralized KDC or decentralized MLS)."""
        return self.groups.get(self.keymode)

    def _current_key(self, source: str) -> tuple[int, bytes] | None:
        # Only the ACTIVE key mode's key is accepted.
        wanted = "decentralized" if source == "mls" else "centralized"
        if wanted != self.keymode or self.group is None:
            return None
        return self.group.current()

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str) -> None:
        if value not in MODES:
            raise ValueError(f"unsupported security mode {value!r} (have: {', '.join(MODES)})")
        self._mode = value

    def next_seq(self) -> int:
        return self.seq.next()

    # --- sending ------------------------------------------------------------------------

    def seal(self, topic: str, body: dict[str, Any]) -> bytes:
        """Wrap an application body for publishing on ``topic``."""
        if self._mode == "off":
            seq = self.next_seq()
            envelope = {"from": self.identity, "seq": seq, "ts": round(time.time(), 3), **body}
            payload = json.dumps(envelope, separators=(",", ":")).encode()
            self.log.info(
                f"mode=off seq={seq} published {len(payload)} bytes on {topic} "
                "(plaintext, no protection)"
            )
            return payload

        current = self.group.current() if self.group else None
        if current is None:
            raise NoGroupKey("no group key yet (waiting for the KDC)")
        epoch, key = current
        raw = json.dumps(body, separators=(",", ":")).encode()
        signer = self.signer if self.requires_signature(topic) else None
        seq = self.next_seq()
        payload = seal(
            topic=topic,
            body=raw,
            sender=self.identity,
            seq=seq,
            epoch=epoch,
            group_key=key,
            ts_ms=int(time.time() * 1000),
            suite=self.suite,
            signer=signer,
            source="mls" if self.keymode == "decentralized" else "kdc",
        )
        self.log.info(
            f"{'mls' if self.keymode == 'decentralized' else 'kdc'}-epoch={epoch} seq={seq} "
            f"aead={self.suite} published {len(payload)} bytes "
            f"(payload {len(raw)} + overhead {len(payload) - len(raw)})"
            f"{' signed' if signer else ''} on {topic}"
        )
        return payload

    # --- receiving ------------------------------------------------------------------------

    def open(self, topic: str, payload: bytes) -> Opened:
        looks_sealed = payload[:1] == b"\x01"  # sealed format version byte
        if self._mode == "off":
            if looks_sealed:
                return Opened(ok=False, reason="sealed message while security is OFF")
            return self._open_plain(payload)
        if payload[:1] == b"{":
            return Opened(ok=False, reason="plaintext refused (security ON)")
        try:
            m = self.opener.open(topic, payload, int(time.time() * 1000))
        except Reject as exc:
            return Opened(ok=False, reason=exc.reason)
        return Opened(True, m.body, m.sender, m.seq, None, m.epoch, m.signed)

    @staticmethod
    def _open_plain(payload: bytes) -> Opened:
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
