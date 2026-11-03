"""Quarantine notices: the hub's signed, versioned list of quarantined devices.

Published retained on `hub/quarantine` (through the untrusted broker). Every
consumer (KDC, devices) verifies the hub's signature with the hub's certified
key and accepts only a HIGHER version than it has seen — so the broker can't
forge a notice, and replaying an old one can't release a quarantined device.
"""

from __future__ import annotations

import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securelib.pki import TrustError

CONTEXT = b"bbiot-quarantine-v1"
TOPIC = "hub/quarantine"


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign_notice(key: Ed25519PrivateKey, version: int, quarantined: dict[str, str]) -> dict:
    notice = {"version": version, "quarantined": quarantined, "ts": int(time.time() * 1000)}
    return {"notice": notice, "sig": key.sign(CONTEXT + _canonical(notice)).hex()}


def verify_notice(signed: dict, hub_key: Ed25519PublicKey) -> dict:
    try:
        notice = signed["notice"]
        hub_key.verify(bytes.fromhex(signed["sig"]), CONTEXT + _canonical(notice))
        int(notice["version"])
        dict(notice["quarantined"])
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise TrustError("quarantine notice is not signed by the hub") from exc
    return notice


class NoticeTracker:
    """Keeps the newest verified notice; ignores forged and older ones."""

    def __init__(self) -> None:
        self.version = -1
        self.quarantined: dict[str, str] = {}

    def offer(self, signed: dict, hub_key: Ed25519PublicKey | None) -> bool:
        """Returns True if the list changed."""
        if hub_key is None:
            return False
        notice = verify_notice(signed, hub_key)
        if notice["version"] <= self.version:
            return False  # replay of an older list
        self.version = notice["version"]
        changed = notice["quarantined"] != self.quarantined
        self.quarantined = dict(notice["quarantined"])
        return changed
