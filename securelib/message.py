"""Sealed message format (security ON).

Wire layout (all integers big-endian):

  header (sent in clear, authenticated as AAD)
    version      1   = 1
    suite        1   1 = AES-256-GCM, 2 = ChaCha20-Poly1305
    epoch        4   group key epoch
    seq          8   sender's sequence number
    ts_ms        8   sender's clock, milliseconds
    topic_tag    4   first 4 bytes of SHA-256(topic) — fast "wrong topic" check
    flags        1   bit 0: body is signed by the sender; bit 1: key from MLS
    sender_len   1
    sender       n   sender device id (UTF-8)
    nonce       12   fresh random per message
  ciphertext         AEAD(message_key(epoch), nonce, [signature(64) ||] body, AAD)

  AAD = "bbiot-msg-v1" || len(topic) || topic || header
  signature = Ed25519(sender key, "bbiot-msg-sig-v1" || AAD || body)

The full topic is bound through the AAD, so a redirected message fails the tag
even if the broker also rewrites topic_tag. The signature sits inside the
ciphertext, so the broker can't strip or swap it unseen.

Receiver checks (cheap ones first; replay state is only updated after the tag
and signature verify):
  malformed → unknown version/suite → wrong topic → wrong epoch → stale
  timestamp → replay → tag invalid → unknown sender / bad signature →
  unsigned command
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
SUITES: dict[int, tuple[str, type]] = {
    1: ("AES-GCM", AESGCM),
    2: ("ChaCha20-Poly1305", ChaCha20Poly1305),
}
SUITE_IDS = {"AES-GCM": 1, "ChaCha20-Poly1305": 2}
_FIXED = struct.Struct(">BBIQQ4sBB")  # version..sender_len
NONCE_LEN, TAG_LEN, SIG_LEN = 12, 16, 64
FLAG_SIGNED = 0x01
FLAG_MLS = 0x02  # sealed with the MLS-exported key (decentralized), else KDC key
AAD_CONTEXT = b"bbiot-msg-v1"
SIG_CONTEXT = b"bbiot-msg-sig-v1"
KEY_INFO = b"bbiot-msg-key-v1"


class Reject(Exception):
    """Message refused. ``reason`` is shown in logs and on the dashboard."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Header:
    version: int
    suite: int
    epoch: int
    seq: int
    ts_ms: int
    topic_tag: bytes
    flags: int
    sender: str
    nonce: bytes
    raw: bytes

    @property
    def signed(self) -> bool:
        return bool(self.flags & FLAG_SIGNED)

    @property
    def source(self) -> str:
        """Which key management produced the key: 'mls' or 'kdc'."""
        return "mls" if self.flags & FLAG_MLS else "kdc"


def topic_tag(topic: str) -> bytes:
    return hashlib.sha256(topic.encode()).digest()[:4]


def message_key(group_key: bytes, epoch: int) -> bytes:
    """Per-epoch message key, separated from the group secret by HKDF."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=KEY_INFO + epoch.to_bytes(4, "big")
    ).derive(group_key)


def encode_header(
    suite: int, epoch: int, seq: int, ts_ms: int, topic: str, flags: int, sender: str, nonce: bytes
) -> bytes:
    sid = sender.encode()
    if not 0 < len(sid) < 256:
        raise ValueError("sender id length")
    return (
        _FIXED.pack(VERSION, suite, epoch, seq, ts_ms, topic_tag(topic), flags, len(sid))
        + sid
        + nonce
    )


def parse_header(payload: bytes) -> tuple[Header, bytes]:
    """Split a sealed payload into (header, ciphertext). Raises Reject('malformed')."""
    if len(payload) < _FIXED.size:
        raise Reject("malformed (too short)")
    version, suite, epoch, seq, ts_ms, tag, flags, slen = _FIXED.unpack_from(payload)
    end = _FIXED.size + slen + NONCE_LEN
    if len(payload) < end + TAG_LEN:
        raise Reject("malformed (truncated)")
    try:
        sender = payload[_FIXED.size : _FIXED.size + slen].decode()
    except UnicodeDecodeError as exc:
        raise Reject("malformed (sender)") from exc
    nonce = payload[end - NONCE_LEN : end]
    header = Header(version, suite, epoch, seq, ts_ms, tag, flags, sender, nonce, payload[:end])
    return header, payload[end:]


def peek_header(payload: bytes) -> Header | None:
    """What anyone (including the broker) can read from a sealed message."""
    try:
        return parse_header(payload)[0]
    except Reject:
        return None


def aad(topic: str, header_raw: bytes) -> bytes:
    t = topic.encode()
    return AAD_CONTEXT + len(t).to_bytes(2, "big") + t + header_raw


def seal(
    *,
    topic: str,
    body: bytes,
    sender: str,
    seq: int,
    epoch: int,
    group_key: bytes,
    ts_ms: int,
    suite: str = "AES-GCM",
    signer: Ed25519PrivateKey | None = None,
    source: str = "kdc",
) -> bytes:
    suite_id = SUITE_IDS[suite]
    nonce = os.urandom(NONCE_LEN)  # fresh random nonce for every message
    flags = (FLAG_SIGNED if signer else 0) | (FLAG_MLS if source == "mls" else 0)
    header = encode_header(suite_id, epoch, seq, ts_ms, topic, flags, sender, nonce)
    a = aad(topic, header)
    plaintext = body
    if signer is not None:
        plaintext = signer.sign(SIG_CONTEXT + a + body) + body
    cipher = SUITES[suite_id][1](message_key(group_key, epoch))
    return header + cipher.encrypt(nonce, plaintext, a)


def decrypt_unchecked(topic: str, payload: bytes, group_key: bytes) -> bytes:
    """Decrypt with no freshness/replay/signature checks (used by the attacker
    tooling to prove it holds a stolen key). Returns the body."""
    header, ct = parse_header(payload)
    cipher = SUITES[header.suite][1](message_key(group_key, header.epoch))
    pt = cipher.decrypt(header.nonce, ct, aad(topic, header.raw))
    return pt[SIG_LEN:] if header.signed else pt


# --- replay protection --------------------------------------------------------------------


class ReplayWindow:
    """Sliding window over sequence numbers (RFC 4303 §3.4.3 style)."""

    def __init__(self, size: int = 64) -> None:
        self.size = size
        self.highest = 0
        self.bitmap = 0  # bit i set => seq (highest - i) seen

    def _span(self) -> str:
        return f"window {max(1, self.highest - self.size + 1)}..{self.highest}"

    def check(self, seq: int) -> None:
        if seq <= 0:
            raise Reject("malformed (seq)")
        if seq > self.highest:
            return
        diff = self.highest - seq
        if diff >= self.size:
            raise Reject(f"replay (seq {seq} too old, {self._span()})")
        if (self.bitmap >> diff) & 1:
            raise Reject(f"replay (seq {seq} already seen, {self._span()})")

    def commit(self, seq: int) -> None:
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = seq
        else:
            self.bitmap |= 1 << (self.highest - seq)


# --- receiving ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenedMessage:
    sender: str
    seq: int
    epoch: int
    ts_ms: int
    signed: bool
    body: dict[str, Any]
    suite: str


class Opener:
    def __init__(
        self,
        *,
        current_key: Callable[[str], tuple[int, bytes] | None],
        sender_key: Callable[[str], Ed25519PublicKey | None],
        requires_signature: Callable[[str], bool],
        max_skew_ms: int = 30_000,
        window: int = 64,
    ) -> None:
        self.current_key = current_key  # source ('kdc' | 'mls') -> (epoch, key) or None
        self.sender_key = sender_key
        self.requires_signature = requires_signature
        self.max_skew_ms = max_skew_ms
        self.window_size = window
        self._windows: dict[str, ReplayWindow] = {}
        self._lock = threading.Lock()

    def open(self, topic: str, payload: bytes, now_ms: int) -> OpenedMessage:
        h, ct = parse_header(payload)
        if h.version != VERSION or h.suite not in SUITES:
            raise Reject(f"malformed (version {h.version} / suite {h.suite})")
        if not hmac.compare_digest(h.topic_tag, topic_tag(topic)):
            raise Reject(f"wrong topic (sealed for another topic, delivered on {topic})")
        cur = self.current_key(h.source)
        if cur is None:
            raise Reject(
                f"no {h.source.upper()} group key (not the active key mode, or not joined yet)"
            )
        current, key = cur
        if h.epoch != current:
            raise Reject(f"wrong epoch (message epoch {h.epoch}, current {current})")
        skew = now_ms - h.ts_ms
        if abs(skew) > self.max_skew_ms:
            raise Reject(
                f"stale timestamp ({skew / 1000:+.1f}s, limit ±{self.max_skew_ms // 1000}s)"
            )

        with self._lock:
            window = self._windows.setdefault(h.sender, ReplayWindow(self.window_size))
            window.check(h.seq)

        a = aad(topic, h.raw)
        try:
            pt = SUITES[h.suite][1](message_key(key, h.epoch)).decrypt(h.nonce, ct, a)
        except InvalidTag as exc:
            raise Reject("tag invalid (modified, forged or wrong key)") from exc

        body_bytes = pt
        if h.signed:
            if len(pt) < SIG_LEN:
                raise Reject("malformed (signature)")
            sig, body_bytes = pt[:SIG_LEN], pt[SIG_LEN:]
            pub = self.sender_key(h.sender)
            if pub is None:
                raise Reject(f"unknown sender {h.sender!r} (no verified certificate)")
            try:
                pub.verify(sig, SIG_CONTEXT + a + body_bytes)
            except InvalidSignature as exc:
                raise Reject(f"bad signature (not signed by {h.sender})") from exc
        elif self.requires_signature(topic):
            raise Reject("unsigned command (signature required on this topic)")

        try:
            body = json.loads(body_bytes)
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError) as exc:
            raise Reject("malformed (body)") from exc

        with self._lock:  # only now, after authentication, record the seq
            window.check(h.seq)  # re-check: a concurrent copy may have won the race
            window.commit(h.seq)
        return OpenedMessage(h.sender, h.seq, h.epoch, h.ts_ms, h.signed, body, SUITES[h.suite][0])

    def window_of(self, sender: str) -> ReplayWindow | None:
        return self._windows.get(sender)
