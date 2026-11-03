"""Key Distribution Center (centralized group-key mode).

The KDC is the trusted party of the *centralized* baseline: it knows every group
key (attack 10 contrasts this with MLS). It talks to devices only over MQTT —
through the untrusted broker — using the signed key exchange in
securelib.kdcproto, and checks every joining device's certificate (root, log,
pin, revocations) first.

Rekeys (new epoch, fresh random key) when:
  * a device joins that is not yet a member (new members can't read old traffic)
  * a member is revoked (revoked devices can't read new traffic)
  * an operator asks (POST /rekey, e.g. after attack 6)
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from securelib.groupkeys import ANNOUNCE_TOPIC, key_topic, session_topic
from securelib.kdcproto import KdcJoin, wrap_key
from securelib.log import get_logger
from securelib.pki import TrustError
from securelib.services import ServiceError
from securelib.trust import PeerVerifier

log = get_logger("kdc")
REKEY_DEBOUNCE = 1.0


class Kdc:
    def __init__(
        self,
        signer: Ed25519PrivateKey,
        verifier: PeerVerifier,
        publish,
        epoch_file: Path,
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.publish = publish  # (topic, dict, retain=False)
        self.epoch_file = epoch_file
        self._lock = threading.RLock()
        self.boot = uuid.uuid4().hex[:12]
        self.epoch = self._load_epoch() + 1
        self._key = os.urandom(32)
        self._save_epoch()
        self.members: dict[str, bytes] = {}  # device -> KEK
        self.member_serial: dict[str, int] = {}  # device -> certificate serial it joined with
        self.pending: dict[str, tuple[KdcJoin, Any]] = {}
        self.allow_unsigned: set[str] = set()
        from hub.quarantine import NoticeTracker

        self.quarantine = NoticeTracker()
        self.revoked: set[str] = set()
        self._rekey_at: float | None = None
        self.history: list[dict] = []

    # --- epochs ----------------------------------------------------------------------------

    def _load_epoch(self) -> int:
        try:
            return int(self.epoch_file.read_text().strip())
        except (OSError, ValueError):
            return 0

    def _save_epoch(self) -> None:
        self.epoch_file.parent.mkdir(parents=True, exist_ok=True)
        self.epoch_file.write_text(str(self.epoch))

    def announce(self) -> None:
        self.publish(ANNOUNCE_TOPIC, {"boot": self.boot, "epoch": self.epoch}, retain=True)
        log.info(f"announced (boot {self.boot}), epoch {self.epoch}; waiting for joins")

    def schedule_rekey(self, reason: str) -> None:
        with self._lock:
            self._rekey_at = time.monotonic() + REKEY_DEBOUNCE
            self._rekey_reason = reason

    def rekey(self, reason: str) -> int:
        with self._lock:
            started = time.perf_counter()
            self.epoch += 1
            self._key = os.urandom(32)
            self._save_epoch()
            self._rekey_at = None
            members = sorted(self.members)
            for dev in members:
                self._send_key(dev)
            ms = (time.perf_counter() - started) * 1000
            self.history.append(
                {"epoch": self.epoch, "reason": reason, "members": members, "ms": round(ms, 2)}
            )
        log.info(
            f"REKEY → epoch {self.epoch} ({reason}); key sent to {len(members)} members "
            f"[{', '.join(members)}] in {ms:.1f} ms"
        )
        return self.epoch

    def _send_key(self, dev: str) -> None:
        self.publish(key_topic(dev), wrap_key(self.members[dev], dev, self.epoch, self._key))

    # --- protocol ------------------------------------------------------------------------------

    def on_message(self, topic: str, payload: bytes) -> None:
        parts = topic.split("/")
        if len(parts) != 3 or parts[:2] != ["kdc", "join"]:
            return
        dev = parts[2]
        try:
            msg = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return
        try:
            if msg.get("t") == "hello":
                self._on_hello(dev, msg)
            elif msg.get("t") == "finish":
                self._on_finish(dev, msg)
        except (TrustError, ServiceError) as exc:
            log.info(f"✗ join refused for {dev}: {exc}")

    def _on_hello(self, dev: str, msg: dict) -> None:
        if msg.get("device") != dev:
            raise TrustError("hello names a different device than its topic")
        join = KdcJoin.from_hello(msg)
        if dev in self.quarantine.quarantined:
            raise TrustError(f"{dev} is quarantined by the hub")
        if join.auth == "unsigned" and dev not in self.allow_unsigned:
            raise TrustError("unsigned key exchange not allowed")
        peer = self.verifier.verify(dev)  # root ✓ log ✓ pin ✓ this cert not revoked ✓
        with self._lock:
            self.pending[dev] = (join, peer.identity)
        log.info(
            f"hello from {dev} ({join.auth}); cert ✓ log leaf #{peer.leaf_index} ✓ → challenge"
        )
        self.publish(session_topic(dev), join.challenge(self.signer))

    def _on_finish(self, dev: str, msg: dict) -> None:
        with self._lock:
            pending = self.pending.pop(dev, None)
        if pending is None:
            return
        join, ident = pending
        kek = join.on_finish(msg, ident.ed25519)
        with self._lock:
            self.allow_unsigned.discard(dev)
            new = dev not in self.members
            self.members[dev] = kek
            self.member_serial[dev] = getattr(ident, "serial", 0)
        how = "signed X25519 DH ✓" if join.auth == "signed" else "⚠ UNSIGNED DH"
        if new:
            log.info(f"✓ {dev} joined ({how}) → rekey so it can't read earlier traffic")
            self.schedule_rekey(f"{dev} joined")
        else:
            log.info(f"✓ {dev} re-joined ({how}) → sending current epoch {self.epoch}")
            with self._lock:
                self._send_key(dev)

    # --- background ---------------------------------------------------------------------------

    def on_quarantine_notice(self, payload: bytes) -> None:
        """Signed by the hub (its certified key); newer versions only."""
        try:
            hub_key = self.verifier.verify("hub").identity.ed25519
            changed = self.quarantine.offer(json.loads(payload), hub_key)
        except (ValueError, TrustError, ServiceError) as exc:
            log.info(f"✗ quarantine notice refused: {exc}")
            return
        if not changed:
            return
        with self._lock:
            hit = sorted(d for d in self.quarantine.quarantined if d in self.members)
            for dev in hit:
                self.members.pop(dev, None)
                self.member_serial.pop(dev, None)
                self.pending.pop(dev, None)
        if hit:
            log.info(f"hub quarantined {', '.join(hit)} → removed from group")
            self.rekey(f"quarantined {', '.join(hit)}")

    def check_revocations(self) -> None:
        """Drop members whose *current* certificate (by serial) has been revoked."""
        revs = self.verifier.revocations()
        self.revoked = set(revs)
        with self._lock:
            hit = sorted(d for d in self.members if self.member_serial.get(d) in revs.get(d, set()))
            for dev in hit:
                self.members.pop(dev, None)
                self.member_serial.pop(dev, None)
                self.pending.pop(dev, None)
        if hit:
            log.info(f"revocation seen for {', '.join(hit)} → removed from group")
            self.rekey(f"revoked {', '.join(hit)}")

    def loop(self) -> None:
        last_rev = 0.0
        while True:
            time.sleep(0.2)
            with self._lock:
                due = self._rekey_at is not None and time.monotonic() >= self._rekey_at
                reason = getattr(self, "_rekey_reason", "membership change")
            if due:
                self.rekey(reason)
            if time.monotonic() - last_rev > 2:
                last_rev = time.monotonic()
                try:
                    self.check_revocations()
                except (TrustError, ServiceError) as exc:
                    log.info(f"revocation check failed: {exc}")

    def status(self) -> dict:
        """Public status — never includes keys."""
        with self._lock:
            return {
                "mode": "centralized",
                "epoch": self.epoch,
                "members": sorted(self.members),
                "revoked": sorted(self.revoked),
                "quarantined": sorted(self.quarantine.quarantined),
                "allow_unsigned": sorted(self.allow_unsigned),
                "history": self.history[-20:],
            }
