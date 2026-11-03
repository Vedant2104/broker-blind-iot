"""HTTPS clients for the key directory and the transparency log.

Both services are untrusted: these clients only fetch data. All checking
happens in securelib.trust.
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

from securelib.config import Config
from securelib.tls import client_paths


class ServiceError(RuntimeError):
    pass


def _ctx(cfg: Config, identity: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(client_paths(cfg.tls_dir, identity).ca))


class _Client:
    def __init__(self, http: httpx.Client, name: str) -> None:
        self.http = http
        self.name = name

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ServiceError(f"{self.name} unreachable: {exc}") from exc
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = r.text
            raise ServiceError(f"{self.name}: {r.status_code} {detail}")
        return r.json()


class DirectoryClient(_Client):
    def __init__(self, http: httpx.Client) -> None:
        super().__init__(http, "directory")

    @classmethod
    def connect(cls, cfg: Config, identity: str) -> DirectoryClient:
        http = httpx.Client(base_url=cfg.directory_url, verify=_ctx(cfg, identity), timeout=5)
        return cls(http)

    def get_cert(self, device_id: str) -> dict | None:
        return self._req("GET", f"/certs/{device_id}")

    def list_certs(self) -> list[dict]:
        return self._req("GET", "/certs") or []

    def publish(self, cert_pem: str, action_id: str | None = None) -> dict:
        return self._req("POST", "/certs", json={"cert_pem": cert_pem, "action_id": action_id})

    def list_revocations(self) -> list[dict]:
        return self._req("GET", "/revocations") or []

    def publish_revocation(self, signed: dict) -> dict:
        return self._req("POST", "/revocations", json={"signed": signed})

    # MLS delivery service
    def mls_put_key_package(self, device_id: str, kp_hex: str) -> dict:
        return self._req("PUT", f"/mls/keypackages/{device_id}", json={"key_package": kp_hex})

    def mls_get_key_package(self, device_id: str) -> str | None:
        r = self._req("GET", f"/mls/keypackages/{device_id}")
        return r["key_package"] if r else None

    def mls_put_handshake(self, msg: dict) -> dict:
        return self._req("POST", "/mls/handshakes", json=msg)

    def mls_handshakes(self, group_id: str, after: int = -1) -> list[dict]:
        params = {"group_id": group_id, "after": after}
        return self._req("GET", "/mls/handshakes", params=params) or []

    # compromised-directory demo controls
    def evil_swap(self, device_id: str, what: str = "both") -> dict:
        return self._req("POST", f"/evil/swap/{device_id}", params={"what": what})

    def evil_clear(self) -> dict:
        return self._req("DELETE", "/evil")

    def evil_dump(self) -> dict:
        return self._req("GET", "/evil/dump")

    def list_actions(self) -> list[dict]:
        return self._req("GET", "/actions") or []

    def get_action(self, action_id: str) -> dict | None:
        return self._req("GET", f"/actions/{action_id}")

    def post_action(self, action: dict, csr_pem: str | None) -> dict:
        return self._req("POST", "/actions", json={"action": action, "csr_pem": csr_pem})

    def approve(self, action_id: str, admin: str, signature: str) -> dict:
        body = {"admin": admin, "signature": signature}
        return self._req("POST", f"/actions/{action_id}/approvals", json=body)


class LogClient(_Client):
    def __init__(self, http: httpx.Client) -> None:
        super().__init__(http, "transparency log")

    @classmethod
    def connect(cls, cfg: Config, identity: str) -> LogClient:
        http = httpx.Client(base_url=cfg.translog_url, verify=_ctx(cfg, identity), timeout=5)
        return cls(http)

    def sth(self) -> dict:
        return self._req("GET", "/sth")

    def inclusion(self, leaf_hash: bytes, tree_size: int) -> dict | None:
        params = {"leaf_hash": leaf_hash.hex(), "tree_size": tree_size}
        return self._req("GET", "/proof/inclusion", params=params)

    def consistency(self, first: int, second: int) -> dict:
        return self._req("GET", "/proof/consistency", params={"first": first, "second": second})

    def add(self, der: bytes) -> dict:
        return self._req("POST", "/entries", json={"leaf": der.hex()})
