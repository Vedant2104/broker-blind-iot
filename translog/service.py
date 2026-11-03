"""Transparency log service: append-only, RFC 6962 style.

Leaves are DER device certificates. Only certificates that chain to the bbiot
root are accepted (like CT logs, this stops spam; it does not make the log
trusted — clients verify signed tree heads and proofs themselves).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from securelib.log import get_logger
from securelib.pki import TreeHead, TrustError, load_root, sth_message, verify_signed_by
from translog import merkle

log = get_logger("translog")


class LogStore:
    """Leaves persisted as one hex line each in ``path`` (append-only file)."""

    def __init__(self, path: Path, key: Ed25519PrivateKey) -> None:
        self.path = path
        self.key = key
        self._lock = threading.Lock()
        self.leaves: list[bytes] = []
        self.hashes: list[bytes] = []
        self._index: dict[bytes, int] = {}
        if path.exists():
            for line in path.read_text("ascii").splitlines():
                if line.strip():
                    self._add(bytes.fromhex(line.strip()))
        path.parent.mkdir(parents=True, exist_ok=True)

    def _add(self, leaf: bytes) -> int:
        h = merkle.leaf_hash(leaf)
        self.leaves.append(leaf)
        self.hashes.append(h)
        self._index[h] = len(self.hashes) - 1
        return len(self.hashes) - 1

    def append(self, leaf: bytes) -> tuple[int, bool]:
        """Returns (index, newly_added). Duplicate leaves keep their first index."""
        with self._lock:
            h = merkle.leaf_hash(leaf)
            if h in self._index:
                return self._index[h], False
            with self.path.open("a", encoding="ascii") as f:
                f.write(leaf.hex() + "\n")
            return self._add(leaf), True

    def sth(self) -> TreeHead:
        with self._lock:
            size, root = len(self.hashes), merkle.root_hash(self.hashes)
        ts = int(time.time() * 1000)
        return TreeHead(size, ts, root, self.key.sign(sth_message(size, ts, root)))

    def index_of(self, h: bytes) -> int | None:
        return self._index.get(h)

    def snapshot(self, size: int) -> list[bytes]:
        with self._lock:
            if not 0 <= size <= len(self.hashes):
                raise ValueError(f"tree size {size} out of range (log has {len(self.hashes)})")
            return self.hashes[:size]


class Entry(BaseModel):
    leaf: str  # hex DER certificate


def create_app(store: LogStore, root_pem: bytes) -> FastAPI:
    root_cert, root_key = load_root(root_pem)
    app = FastAPI(title="bbiot transparency log")

    @app.get("/sth")
    def get_sth() -> dict:
        return store.sth().as_json()

    @app.post("/entries")
    def add_entry(body: Entry) -> dict:
        try:
            der = bytes.fromhex(body.leaf)
            cert = x509.load_der_x509_certificate(der)
            if cert.issuer != root_cert.subject:
                raise TrustError("issuer is not the bbiot root")
            verify_signed_by(cert, root_key)
        except (ValueError, TrustError) as exc:
            raise HTTPException(422, f"rejected: {exc}") from exc
        index, new = store.append(der)
        sth = store.sth()
        if new:
            cn = cert.subject.rfc4514_string()
            log.info(f"appended leaf #{index} ({cn}), tree size {sth.tree_size}")
        return {"index": index, "leaf_hash": merkle.leaf_hash(der).hex(), "sth": sth.as_json()}

    @app.get("/entries")
    def entries(start: int = 0, end: int | None = None) -> list[dict]:
        end = len(store.leaves) if end is None else min(end, len(store.leaves))
        return [{"index": i, "leaf": store.leaves[i].hex()} for i in range(max(start, 0), end)]

    @app.get("/proof/inclusion")
    def inclusion(leaf_hash: str, tree_size: int) -> dict:
        try:
            h = bytes.fromhex(leaf_hash)
            hashes = store.snapshot(tree_size)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        index = store.index_of(h)
        if index is None or index >= tree_size:
            raise HTTPException(404, "leaf not in tree of that size")
        path = merkle.inclusion_proof(index, hashes)
        return {"index": index, "tree_size": tree_size, "path": [p.hex() for p in path]}

    @app.get("/proof/consistency")
    def consistency(first: int, second: int) -> dict:
        try:
            hashes = store.snapshot(second)
            path = merkle.consistency_proof(first, hashes) if 0 < first < second else []
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"first": first, "second": second, "path": [p.hex() for p in path]}

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "size": len(store.hashes)}

    return app
