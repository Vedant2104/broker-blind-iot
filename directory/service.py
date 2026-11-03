"""Key directory: device_id -> signed certificate (public keys only).

It holds no private keys and no group secrets. It is untrusted: clients check
every certificate against the root and the transparency log themselves. It also
serves as a bulletin board for pending admin actions; the approvals posted there
are signatures the offline root re-verifies before signing anything.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography import x509
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from rootca import approvals
from securelib.log import get_logger
from securelib.pki import TrustError, load_root, verify_device_cert, verify_revocation

log = get_logger("directory")


class DirectoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.data: dict[str, Any] = {
            "certs": {},
            "actions": {},
            "revocations": {},
            "key_packages": {},
            "handshakes": [],
        }
        if path.exists():
            self.data = {**self.data, **json.loads(path.read_text("utf-8"))}
        path.parent.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def update(self, fn: Callable[[dict[str, Any]], Any]) -> Any:
        with self._lock:
            result = fn(self.data)
            self.save()
            return result


class CertBody(BaseModel):
    cert_pem: str
    action_id: str | None = None


class ActionBody(BaseModel):
    action: dict[str, Any]
    csr_pem: str | None = None


class RevocationBody(BaseModel):
    signed: dict[str, Any]


class KeyPackageBody(BaseModel):
    key_package: str


class ApprovalBody(BaseModel):
    admin: str
    signature: str


def create_app(
    store: DirectoryStore, root_pem: bytes, roster: dict, submit_to_log: Callable[[bytes], dict]
) -> FastAPI:
    root_cert, root_key = load_root(root_pem)
    app = FastAPI(title="bbiot key directory")

    def public_cert_view(entry: dict) -> dict:
        return {k: entry[k] for k in ("device_id", "cert_pem", "leaf_index", "fingerprint")}

    # Compromised-directory state (attacks 9/10). Lives only in memory.
    evil: dict[str, dict] = {}

    def served(entry: dict) -> dict:
        forged = evil.get(entry["device_id"])
        if forged and forged.get("cert_pem"):
            return {**public_cert_view(entry), "cert_pem": forged["cert_pem"]}
        return public_cert_view(entry)

    @app.get("/certs")
    def list_certs() -> list[dict]:
        return [served(e) for e in store.data["certs"].values()]

    @app.get("/certs/{device_id}")
    def get_cert(device_id: str) -> dict:
        entry = store.data["certs"].get(device_id)
        if entry is None:
            raise HTTPException(404, f"no certificate for {device_id!r}")
        return served(entry)

    # --- MLS: public key packages + handshake delivery service ------------------------

    @app.put("/mls/keypackages/{device_id}")
    def put_key_package(device_id: str, body: KeyPackageBody) -> dict:
        if device_id not in store.data["certs"]:
            raise HTTPException(404, f"{device_id!r} has no certificate")
        store.update(lambda d: d["key_packages"].__setitem__(device_id, body.key_package))
        return {"device_id": device_id}

    @app.get("/mls/keypackages/{device_id}")
    def get_key_package(device_id: str) -> dict:
        if device_id in evil and evil[device_id].get("key_package"):
            return {"key_package": evil[device_id]["key_package"]}
        kp = store.data["key_packages"].get(device_id)
        if kp is None:
            raise HTTPException(404, f"no key package for {device_id!r}")
        return {"key_package": kp}

    @app.post("/mls/handshakes")
    def put_handshake(body: dict[str, Any]) -> dict:
        def apply(d: dict) -> None:
            d["handshakes"].append(body)
            del d["handshakes"][:-500]

        store.update(apply)
        return {"stored": len(store.data["handshakes"])}

    @app.get("/mls/handshakes")
    def get_handshakes(group_id: str, after: int = -1) -> list[dict]:
        found = [
            h
            for h in store.data["handshakes"]
            if h.get("group_id") == group_id and int(h.get("epoch", -1)) > after
        ]
        return sorted(found, key=lambda h: int(h["epoch"]))

    # --- compromised directory (demo attacks; localhost only) ----------------------------

    @app.post("/evil/swap/{device_id}")
    def evil_swap(device_id: str, what: str = "both") -> dict:
        from directory.evil import forge_device_cert, forge_key_package

        if device_id not in store.data["certs"]:
            raise HTTPException(404, f"{device_id!r} has no certificate")
        cert_pem, attacker = forge_device_cert(device_id, root_cert)
        evil[device_id] = {
            "cert_pem": cert_pem if what in ("cert", "both") else None,
            "key_package": (
                forge_key_package(device_id, attacker) if what in ("keypackage", "both") else None
            ),
        }
        log.info(
            f"☠ COMPROMISED: now serving the attacker's certificate + key package for {device_id}"
        )
        return {"device_id": device_id, "key_package_forged": bool(evil[device_id]["key_package"])}

    @app.delete("/evil")
    def evil_clear() -> dict:
        evil.clear()
        log.info("evil mode off: serving genuine entries again")
        return {"ok": True}

    @app.get("/evil/dump")
    def evil_dump() -> dict:
        """Everything a compromised directory holds — for attack 10."""
        log.info("☠ COMPROMISED: full database dump handed to the attacker")
        return store.data

    @app.post("/certs")
    def publish(body: CertBody) -> dict:
        try:
            cert = x509.load_pem_x509_certificate(body.cert_pem.encode())
            ident = verify_device_cert(cert, root_cert, root_key)
        except (ValueError, TrustError) as exc:
            raise HTTPException(422, f"rejected: {exc}") from exc
        logged = submit_to_log(ident.der)
        entry = {
            "device_id": ident.device_id,
            "cert_pem": body.cert_pem,
            "leaf_index": logged["index"],
            "fingerprint": ident.fingerprint,
            "serial": format(ident.serial, "x"),
            "published_ms": int(time.time() * 1000),
        }

        def apply(d: dict) -> None:
            d["certs"][ident.device_id] = entry
            if body.action_id and body.action_id in d["actions"]:
                d["actions"][body.action_id]["status"] = "issued"

        store.update(apply)
        log.info(
            f"published {ident.device_id} fp={ident.fingerprint[:23]}… "
            f"(log leaf #{logged['index']}, tree size {logged['sth']['tree_size']})"
        )
        return {**public_cert_view(entry), "sth": logged["sth"]}

    @app.get("/revocations")
    def list_revocations() -> list[dict]:
        return list(store.data["revocations"].values())

    @app.post("/revocations")
    def revoke(body: RevocationBody) -> dict:
        try:
            device_id, serial = verify_revocation(body.signed, root_key)
        except TrustError as exc:
            raise HTTPException(422, f"rejected: {exc}") from exc

        def apply(d: dict) -> None:
            d["revocations"][device_id] = body.signed
            action_id = body.signed["revocation"].get("action_id")
            if action_id in d["actions"]:
                d["actions"][action_id]["status"] = "issued"

        store.update(apply)
        log.info(f"REVOKED {device_id} (serial {serial:x}) — root-signed revocation published")
        return body.signed

    # --- admin action bulletin board -----------------------------------------------------

    @app.get("/actions")
    def list_actions() -> list[dict]:
        return list(store.data["actions"].values())

    @app.get("/actions/{action_id}")
    def get_action(action_id: str) -> dict:
        entry = store.data["actions"].get(action_id)
        if entry is None:
            raise HTTPException(404, f"no action {action_id!r}")
        return entry

    @app.post("/actions")
    def post_action(body: ActionBody) -> dict:
        action = body.action
        try:
            approvals.check_device_id(str(action.get("device_id", "")))
            if action.get("type") not in approvals.ACTION_TYPES:
                raise TrustError("unknown action type")
            if action["type"] == "add-device":
                csr = (body.csr_pem or "").encode()
                if hashlib.sha256(csr).hexdigest() != action.get("csr_sha256"):
                    raise TrustError("CSR does not match the action")
        except (TrustError, KeyError) as exc:
            raise HTTPException(422, f"rejected: {exc}") from exc
        aid = approvals.action_id(action)
        entry = {
            "id": aid,
            "action": action,
            "csr_pem": body.csr_pem,
            "approvals": {},
            "status": "pending",
        }
        store.update(lambda d: d["actions"].setdefault(aid, entry))
        log.info(f"action {aid} posted: {action['type']} {action['device_id']}")
        return store.data["actions"][aid]

    @app.post("/actions/{action_id}/approvals")
    def approve(action_id: str, body: ApprovalBody) -> dict:
        entry = store.data["actions"].get(action_id)
        if entry is None:
            raise HTTPException(404, f"no action {action_id!r}")
        trial = {**entry["approvals"], body.admin: body.signature}
        if body.admin not in approvals.valid_approvers(entry["action"], trial, roster):
            raise HTTPException(422, f"approval by {body.admin!r} does not verify")

        def apply(d: dict) -> dict:
            d["actions"][action_id]["approvals"][body.admin] = body.signature
            return d["actions"][action_id]

        updated = store.update(apply)
        n = len(updated["approvals"])
        log.info(f"action {action_id}: admin {body.admin} approved ({n}/{roster['threshold']})")
        return updated

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "certs": len(store.data["certs"])}

    return app
