"""Group key management behind one interface.

    current() -> (epoch, key) | None      key_for(epoch) -> key | None
    subscriptions() / handle(topic, payload) / tick() / status()

``CentralizedGroupKeys`` gets the key from the KDC over a signed X25519 key
exchange (securelib.kdcproto). ``decentralized`` (MLS) arrives in phase 5 behind
the same interface. Only the current epoch's key is kept: messages under any
other epoch are rejected ("wrong epoch").
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securelib.kdcproto import DeviceJoin, unwrap_key
from securelib.log import get_logger
from securelib.pki import TrustError

ANNOUNCE_TOPIC = "kdc/announce"
RETRY_SECONDS = 8.0


class GroupKeys(Protocol):
    mode: str

    def current(self) -> tuple[int, bytes] | None: ...
    def key_for(self, epoch: int) -> bytes | None: ...
    def subscriptions(self) -> list[str]: ...
    def handle(self, topic: str, payload: bytes) -> None: ...
    def tick(self) -> None: ...
    def status(self) -> dict[str, Any]: ...


def join_topic(device: str) -> str:
    return f"kdc/join/{device}"


def session_topic(device: str) -> str:
    return f"kdc/session/{device}"


def key_topic(device: str) -> str:
    return f"kdc/key/{device}"


class CentralizedGroupKeys:
    mode = "centralized"

    def __init__(
        self,
        device_id: str,
        signer: Ed25519PrivateKey,
        kdc_key: Callable[[], Ed25519PublicKey | None],
        publish: Callable[[str, dict], None],
        may_join: Callable[[], bool],
        on_alert: Callable[[str, str, str], None],
    ) -> None:
        self.device_id = device_id
        self.signer = signer
        self.kdc_key = kdc_key
        self.publish = publish
        self.may_join = may_join
        self.on_alert = on_alert
        self.log = get_logger("securelib")
        self._lock = threading.Lock()
        self._join: DeviceJoin | None = None
        self._join_at = 0.0
        self._kek: bytes | None = None
        self._epoch: int | None = None
        self._key: bytes | None = None
        self._kdc_boot: str | None = None
        self._next_auth = "signed"

    # --- interface ---------------------------------------------------------------------

    def current(self) -> tuple[int, bytes] | None:
        with self._lock:
            return (self._epoch, self._key) if self._key is not None else None  # type: ignore[return-value]

    def key_for(self, epoch: int) -> bytes | None:
        with self._lock:
            return self._key if epoch == self._epoch else None

    @property
    def epoch(self) -> int | None:
        return self._epoch

    def subscriptions(self) -> list[str]:
        return [ANNOUNCE_TOPIC, session_topic(self.device_id), key_topic(self.device_id)]

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "epoch": self._epoch, "session": self._kek is not None}

    # --- protocol ------------------------------------------------------------------------

    def start_join(self, auth: str = "signed") -> None:
        if not self.may_join():
            return
        with self._lock:
            self._join = DeviceJoin(self.device_id, auth=auth)
            self._join_at = time.monotonic()
            hello = self._join.hello()
        self.log.info(f"→ KDC join: {auth} X25519 key exchange")
        self.publish(join_topic(self.device_id), hello)

    def rejoin(self, auth: str = "signed") -> None:
        with self._lock:
            self._kek = None
        self.start_join(auth)

    def handle(self, topic: str, payload: bytes) -> None:
        try:
            msg = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return
        if topic == ANNOUNCE_TOPIC:
            boot = msg.get("boot")
            if boot and boot != self._kdc_boot:
                self._kdc_boot = boot
                self.start_join()
        elif topic == session_topic(self.device_id) and msg.get("t") == "challenge":
            self._on_challenge(msg)
        elif topic == key_topic(self.device_id) and msg.get("t") == "key":
            self._on_key(msg)

    def _on_challenge(self, msg: dict) -> None:
        with self._lock:
            join = self._join
        kdc_key = self.kdc_key()
        if join is None or kdc_key is None:
            return
        try:
            finish, kek = join.on_challenge(msg, kdc_key, self.signer)
        except TrustError as exc:
            self.log.info(f"✗ key exchange REJECTED: {exc}")
            self.on_alert("critical", f"{self.device_id}: key exchange rejected", str(exc))
            with self._lock:
                self._join = None
            return
        with self._lock:
            self._kek = kek
            self._join = None
        if join.auth == "signed":
            self.log.info("✓ KDC signature verified (cert from root) — sending signed finish")
        else:
            self.log.info("⚠ UNSIGNED key exchange completed — nobody verified the other side")
        self.publish(join_topic(self.device_id), finish)

    def _on_key(self, msg: dict) -> None:
        with self._lock:
            kek = self._kek
        if kek is None:
            return
        try:
            epoch, key = unwrap_key(kek, self.device_id, msg)
        except TrustError as exc:
            self.log.info(f"✗ {exc} — re-joining")
            self.rejoin()
            return
        with self._lock:
            if self._epoch is not None and epoch <= self._epoch:
                return  # old or repeated key message
            self._epoch, self._key = epoch, key
        self.log.info(f"group key epoch={epoch} installed (centralized, from KDC)")

    def tick(self) -> None:
        with self._lock:
            waiting = self._key is None or (self._join is not None)
            stale = time.monotonic() - self._join_at > RETRY_SECONDS
        if waiting and stale:
            self.start_join()
