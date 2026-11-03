"""Background trust checks a device runs: is *my* certificate in the directory,
root-signed, logged, and for *my* keys? And for every peer: root ✓, log ✓, pin ✓.

Results feed the device snapshot (dashboard badges) and raise alerts on key
changes or a misbehaving directory/log.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

from securelib.pki import TrustError
from securelib.services import ServiceError
from securelib.trust import KeyChanged, PeerVerifier

if TYPE_CHECKING:
    from devices.base import DeviceBase

PENDING_INTERVAL = 3.0
TRUSTED_INTERVAL = 15.0


class TrustWatch:
    def __init__(self, device: DeviceBase) -> None:
        self.d = device
        self.own: dict[str, Any] = {"status": "unverified", "detail": "not checked yet"}
        self.peers: dict[str, dict[str, Any]] = {}
        self._verifier: PeerVerifier | None = None
        self._last_problem: str | None = None

    @property
    def trusted(self) -> bool:
        return self.own["status"] == "trusted"

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="trustwatch").start()

    def _loop(self) -> None:
        while True:
            try:
                self.check_once()
                self._last_problem = None
            except (TrustError, ServiceError, OSError) as exc:
                problem = str(exc)
                if problem != self._last_problem:
                    self.d.log.info(f"trust check: {problem}")
                    self._last_problem = problem
            time.sleep(TRUSTED_INTERVAL if self.trusted else PENDING_INTERVAL)

    def _verifier_or_build(self) -> PeerVerifier:
        if self._verifier is None:
            self._verifier = PeerVerifier.for_identity(
                self.d.cfg, self.d.dev.id, self.d.keys.key_dir / "trust"
            )
        return self._verifier

    def check_once(self) -> None:
        v = self._verifier_or_build()
        entries = {e["device_id"]: e for e in v.directory.list_certs()}
        self._check_own(v, entries.get(self.d.dev.id))
        for dev_id, entry in entries.items():
            if dev_id != self.d.dev.id:
                self._check_peer(v, dev_id, entry)

    def _set_own(self, status: str, detail: str, **extra: Any) -> None:
        changed = self.own.get("status") != status or self.own.get("detail") != detail
        self.own = {"status": status, "detail": detail, **extra}
        if changed:
            mark = "✓" if status == "trusted" else "…" if status == "pending" else "✗"
            self.d.log.info(f"{mark} identity: {detail}")

    def _check_own(self, v: PeerVerifier, entry: dict | None) -> None:
        if entry is None:
            self._set_own(
                "pending", f"not commissioned yet — pairing code {self.d.keys.pairing_code}"
            )
            return
        try:
            peer = v.verify(self.d.dev.id, entry)
        except KeyChanged:
            v.pins.forget(self.d.dev.id)  # own key pin is just our key; re-check below
            peer = v.verify(self.d.dev.id, entry)
        except TrustError as exc:
            self._set_own("invalid", f"my certificate is not trustworthy: {exc}")
            self.d.alert("critical", f"{self.d.dev.id}: own certificate rejected", str(exc))
            return
        if peer.identity.fingerprint != self.d.keys.fingerprint:
            reason = "directory serves a certificate for DIFFERENT keys than mine"
            self._set_own("invalid", reason)
            self.d.alert("critical", f"{self.d.dev.id}: certificate key mismatch", reason)
            return
        self.d.keys.cert_path.write_text(entry["cert_pem"], encoding="utf-8")
        self._set_own(
            "trusted",
            f"certificate verified (root ✓, log leaf #{peer.leaf_index} ✓, tree size "
            f"{peer.tree_size})",
            leaf_index=peer.leaf_index,
        )

    def _check_peer(self, v: PeerVerifier, dev_id: str, entry: dict) -> None:
        before = self.peers.get(dev_id, {}).get("status")
        try:
            peer = v.verify(dev_id, entry)
            info = {
                "status": "trusted",
                "fingerprint": peer.identity.fingerprint,
                "leaf_index": peer.leaf_index,
            }
            if before != "trusted":
                self.d.channel.log.info(
                    f"✓ peer {dev_id}: root ✓ log leaf #{peer.leaf_index} ✓ "
                    f"(tree {peer.tree_size}) {peer.pin} fp={peer.identity.fingerprint[:23]}…"
                )
        except KeyChanged as exc:
            info = {"status": "key-changed", "reason": str(exc)}
            if before != "key-changed":
                self.d.channel.log.info(f"✗ peer {dev_id}: {exc}")
                self.d.alert("critical", f"Key changed for {dev_id}", str(exc))
        except TrustError as exc:
            info = {"status": "untrusted", "reason": str(exc)}
            if before != "untrusted":
                self.d.channel.log.info(f"✗ peer {dev_id}: {exc}")
                self.d.alert("warning", f"{dev_id} failed verification", str(exc))
        self.peers[dev_id] = info

    def snapshot(self) -> dict[str, Any]:
        return {
            "fingerprint": self.d.keys.fingerprint,
            "pairing_code": self.d.keys.pairing_code,
            "cert": self.own,
            "peers": dict(self.peers),
        }
