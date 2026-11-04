"""2-of-3 admin approvals for sensitive actions (add / remove device).

An action is a small JSON object. Its digest (SHA-256 over canonical JSON) is
what admins sign, with a domain-separation prefix. The admin roster (public
keys + threshold) is itself signed by the offline root.

Simple multi-signature: a set of independent Ed25519 signatures; an action is
approved when at least ``threshold`` *distinct* roster admins signed it.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securelib.pki import TrustError

APPROVAL_CONTEXT = b"bbiot-admin-approval-v1"
ROSTER_CONTEXT = b"bbiot-admin-roster-v1"
ACTION_TYPES = ("add-device", "remove-device")
ADMINS = ("A", "B", "C")
THRESHOLD = 2
# A pending add/remove action must be approved and issued within this time. Stale
# actions (a forgotten request, a test run) can't be approved later by surprise.
ACTION_TTL_MS = 60 * 60 * 1000
DEVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
RESERVED_IDS = {
    "root",
    "translog",
    "directory",
    "broker",
    "cli",
    "dashboard",
    "evil-proxy",
    "kdc",
    "counterfeit",
    "admin-console",
}


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def check_device_id(device_id: str) -> None:
    if not DEVICE_ID.match(device_id) or device_id in RESERVED_IDS:
        raise TrustError(f"invalid device id {device_id!r}")


def new_action(kind: str, device_id: str, csr_pem: bytes | None = None) -> dict[str, Any]:
    if kind not in ACTION_TYPES:
        raise TrustError(f"unknown action type {kind!r}")
    check_device_id(device_id)
    action: dict[str, Any] = {
        "type": kind,
        "device_id": device_id,
        "created_ms": int(time.time() * 1000),
        "nonce": secrets.token_hex(8),
    }
    if kind == "add-device":
        if not csr_pem:
            raise TrustError("add-device needs the device's CSR")
        action["csr_sha256"] = hashlib.sha256(csr_pem).hexdigest()
    return action


def action_digest(action: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical(action)).digest()


def action_id(action: dict[str, Any]) -> str:
    return action_digest(action).hex()[:12]


def approval_message(action: dict[str, Any]) -> bytes:
    return APPROVAL_CONTEXT + action_digest(action)


def sign_approval(admin_key: Ed25519PrivateKey, action: dict[str, Any]) -> str:
    return admin_key.sign(approval_message(action)).hex()


# --- roster -------------------------------------------------------------------------------


def make_roster(admin_pubs: dict[str, bytes], threshold: int = THRESHOLD) -> dict[str, Any]:
    return {"threshold": threshold, "admins": {k: v.hex() for k, v in sorted(admin_pubs.items())}}


def sign_roster(root_key: Ed25519PrivateKey, roster: dict[str, Any]) -> dict[str, Any]:
    return {"roster": roster, "signature": root_key.sign(ROSTER_CONTEXT + canonical(roster)).hex()}


def verify_roster(signed: dict[str, Any], root_key: Ed25519PublicKey) -> dict[str, Any]:
    try:
        roster = signed["roster"]
        root_key.verify(bytes.fromhex(signed["signature"]), ROSTER_CONTEXT + canonical(roster))
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise TrustError("admin roster is not signed by the root") from exc
    if int(roster["threshold"]) < 2 or int(roster["threshold"]) > len(roster["admins"]):
        raise TrustError("admin roster has an unsafe threshold")
    return roster


# --- verification ----------------------------------------------------------------------------


def valid_approvers(
    action: dict[str, Any], approvals: dict[str, str], roster: dict[str, Any]
) -> list[str]:
    """Distinct roster admins whose signature over this exact action verifies."""
    msg = approval_message(action)
    ok = []
    for admin, sig_hex in approvals.items():
        pub_hex = roster["admins"].get(admin)
        if pub_hex is None:
            continue  # not an admin
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                bytes.fromhex(sig_hex), msg
            )
        except (ValueError, InvalidSignature):
            continue
        ok.append(admin)
    return sorted(set(ok))


def is_expired(action: dict[str, Any], now_ms: int | None = None) -> bool:
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    return now_ms - int(action.get("created_ms", 0)) > ACTION_TTL_MS


def check_fresh(action: dict[str, Any], now_ms: int | None = None) -> None:
    if is_expired(action, now_ms):
        minutes = ACTION_TTL_MS // 60_000
        raise TrustError(f"action expired (older than {minutes} min) — start it again")


def require_threshold(
    action: dict[str, Any], approvals: dict[str, str], roster: dict[str, Any]
) -> list[str]:
    check_fresh(action)  # the root never acts on a stale approval
    approvers = valid_approvers(action, approvals, roster)
    need = int(roster["threshold"])
    if len(approvers) < need:
        have = ", ".join(approvers) or "none"
        raise TrustError(f"needs {need} admin approvals, has {len(approvers)} valid ({have})")
    return approvers
