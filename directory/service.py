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
from securelib.pki import TrustError, load_root, verify_device_cert

log = get_logger("directory")


class DirectoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.data: dict[str, dict[str, Any]] = {"certs": {}, "actions": {}}
        if path.exists():
            self.data = json.loads(path.read_text("utf-8"))
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

    @app.get("/certs")
    def list_certs() -> list[dict]:
        return [public_cert_view(e) for e in store.data["certs"].values()]

    @app.get("/certs/{device_id}")
    def get_cert(device_id: str) -> dict:
        entry = store.data["certs"].get(device_id)
        if entry is None:
            raise HTTPException(404, f"no certificate for {device_id!r}")
        return public_cert_view(entry)

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
