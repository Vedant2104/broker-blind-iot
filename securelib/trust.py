"""Deciding whether to trust a peer's keys.

For every peer certificate the directory serves, a device checks:
  1. the certificate is signed by the offline root, for that device id
  2. the log's signed tree head (STH) is signed by the root-certified log key
  3. the new STH is consistent with the last one this device saw (no forked log)
  4. the certificate is included in the log at that STH
  5. the keys match the pin from first sight (TOFU on top of the PKI)
Any failure raises TrustError with the reason. Nothing here logs secrets.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from securelib.config import Config
from securelib.pki import (
    DeviceIdentity,
    TreeHead,
    TrustError,
    load_root,
    verify_device_cert,
    verify_revocation,
    verify_service_cert,
    verify_sth,
)
from securelib.services import DirectoryClient, LogClient
from translog import merkle


class KeyChanged(TrustError):
    pass


class Revoked(TrustError):
    pass


class TrustAnchors:
    """Root certificate and the root-certified transparency-log key."""

    def __init__(self, public_dir: Path) -> None:
        root_path = public_dir / "root.crt"
        if not root_path.is_file():
            raise TrustError(f"no root certificate at {root_path.as_posix()} (run: bbiot pki init)")
        self.root, self.root_key = load_root(root_path.read_bytes())
        log_cert = x509.load_pem_x509_certificate((public_dir / "translog.crt").read_bytes())
        self.log_key = verify_service_cert(log_cert, self.root, self.root_key, "translog")
        kdc_path = public_dir / "kdc.crt"
        self.kdc_key = None
        if kdc_path.is_file():
            kdc_cert = x509.load_pem_x509_certificate(kdc_path.read_bytes())
            self.kdc_key = verify_service_cert(kdc_cert, self.root, self.root_key, "kdc")

    @classmethod
    def from_config(cls, cfg: Config) -> TrustAnchors:
        return cls(cfg.pki_public_dir)

    def revoked(self, signed_list: list[dict]) -> dict[str, set[int]]:
        """Verified revocations: device id -> revoked certificate serials.
        Entries not signed by the root are ignored."""
        out: dict[str, set[int]] = {}
        for signed in signed_list:
            try:
                dev, serial = verify_revocation(signed, self.root_key)
            except TrustError:
                continue
            out.setdefault(dev, set()).add(serial)
        return out

    def verify_cert_pem(self, pem: str | bytes, expected_id: str | None = None) -> DeviceIdentity:
        if isinstance(pem, str):
            pem = pem.encode()
        try:
            cert = x509.load_pem_x509_certificate(pem)
        except ValueError as exc:
            raise TrustError("unparseable certificate") from exc
        return verify_device_cert(cert, self.root, self.root_key, expected_id=expected_id)


class _JsonFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)


class PinStore(_JsonFile):
    """device id -> fingerprint pinned at first sight."""

    def check(self, device_id: str, fingerprint: str) -> str:
        with self._lock:
            pins = self.load()
            pinned = pins.get(device_id)
            if pinned is None:
                pins[device_id] = fingerprint
                self.save(pins)
                return "pinned (first sight)"
            if pinned != fingerprint:
                raise KeyChanged(
                    f"KEY CHANGED for {device_id}: pinned {pinned[:23]}…, "
                    f"directory now serves {fingerprint[:23]}…"
                )
            return "matches pin"

    def forget(self, device_id: str) -> None:
        with self._lock:
            pins = self.load()
            pins.pop(device_id, None)
            self.save(pins)


class TreeHeadState(_JsonFile):
    """The latest verified STH, to detect a log that forks or shrinks."""

    def last(self) -> TreeHead | None:
        data = self.load()
        return TreeHead.from_json(data) if data else None

    def store(self, sth: TreeHead) -> None:
        with self._lock:
            self.save(sth.as_json())


@dataclass(frozen=True)
class VerifiedPeer:
    identity: DeviceIdentity
    leaf_index: int
    tree_size: int
    pin: str


class LogVerifier:
    def __init__(self, anchors: TrustAnchors, log: LogClient, state: TreeHeadState) -> None:
        self.anchors = anchors
        self.log = log
        self.state = state
        self._lock = threading.Lock()

    def fresh_sth(self) -> tuple[TreeHead, TreeHead | None]:
        """Fetch, verify and remember the current STH. Returns (new, previous)."""
        with self._lock:
            sth = TreeHead.from_json(self.log.sth())
            verify_sth(sth, self.anchors.log_key)
            prev = self.state.last()
            if prev is not None:
                if sth.tree_size < prev.tree_size:
                    raise TrustError(
                        f"log shrank from {prev.tree_size} to {sth.tree_size} entries (fork)"
                    )
                proof = self.log.consistency(prev.tree_size, sth.tree_size)
                path = [bytes.fromhex(h) for h in proof["path"]]
                if not merkle.verify_consistency(
                    prev.tree_size, sth.tree_size, prev.root_hash, sth.root_hash, path
                ):
                    raise TrustError(
                        f"log is not consistent with the tree head seen before "
                        f"(size {prev.tree_size} -> {sth.tree_size}): history rewritten"
                    )
            self.state.store(sth)
            return sth, prev

    def check_inclusion(self, der: bytes, sth: TreeHead) -> int:
        h = merkle.leaf_hash(der)
        proof = self.log.inclusion(h, sth.tree_size)
        if proof is None:
            raise TrustError("certificate is NOT in the transparency log")
        path = [bytes.fromhex(p) for p in proof["path"]]
        if not merkle.verify_inclusion(proof["index"], sth.tree_size, h, path, sth.root_hash):
            raise TrustError("inclusion proof does not verify against the signed tree head")
        return int(proof["index"])


class PeerVerifier:
    def __init__(
        self,
        anchors: TrustAnchors,
        directory: DirectoryClient,
        log: LogVerifier,
        pins: PinStore,
    ) -> None:
        self.anchors = anchors
        self.directory = directory
        self.log = log
        self.pins = pins

    @classmethod
    def for_identity(cls, cfg: Config, identity: str, state_dir: Path) -> PeerVerifier:
        anchors = TrustAnchors.from_config(cfg)
        log = LogVerifier(
            anchors, LogClient.connect(cfg, identity), TreeHeadState(state_dir / "sth.json")
        )
        return cls(
            anchors, DirectoryClient.connect(cfg, identity), log, PinStore(state_dir / "pins.json")
        )

    def revocations(self) -> dict[str, set[int]]:
        return self.anchors.revoked(self.directory.list_revocations())

    def verify(
        self, device_id: str, entry: dict | None = None, revoked: dict[str, set[int]] | None = None
    ) -> VerifiedPeer:
        entry = entry or self.directory.get_cert(device_id)
        if entry is None:
            raise TrustError(f"directory has no certificate for {device_id}")
        ident = self.anchors.verify_cert_pem(entry["cert_pem"], expected_id=device_id)
        if revoked is None:
            revoked = self.revocations()
        if ident.serial in revoked.get(device_id, set()):
            raise Revoked(
                f"{device_id} is REVOKED (root-signed revocation, serial {ident.serial:x})"
            )
        sth, _ = self.log.fresh_sth()
        index = self.log.check_inclusion(ident.der, sth)
        pin = self.pins.check(device_id, ident.fingerprint)
        return VerifiedPeer(ident, index, sth.tree_size, pin)
