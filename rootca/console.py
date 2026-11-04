"""Admin console: the admins' signing station, so the dashboard can show 2-of-3 approvals.

It mounts the offline admin keys and root key read-only and does exactly one thing:
approve a pending action as admin A, B or C (the same `pki_actions.approve` code the
`bbiot admin approve` command runs; at 2 of 3 the root issues the certificate).

- HTTPS with mutual TLS (transport CA). Only the ``dashboard`` and ``cli`` client
  identities are accepted, so a compromised device cannot ask it to sign.
- Every approval is still checked by the directory against the signed admin roster.
- Stop the container and the keys are "offline" again: dashboard approvals fail,
  the host CLI keeps working.
"""

from __future__ import annotations

import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

from cli import pki_actions
from rootca.approvals import ADMINS
from securelib.config import Config
from securelib.log import get_logger
from securelib.pki import TrustError
from securelib.services import ServiceError
from securelib.tls import client_paths

log = get_logger("admin-console")

IDENTITY = "admin-console"
ALLOWED_CALLERS = frozenset({"dashboard", "cli"})
ACTION_ID = re.compile(r"^[0-9a-f]{12}$")


class ConsoleError(RuntimeError):
    pass


def key_status(cfg: Config) -> dict[str, Any]:
    """Which offline keys this console can reach (never the keys themselves)."""
    paths = pki_actions.pki_paths(cfg)
    return {
        "admins": [a for a in ADMINS if paths.admin_key(a).is_file()],
        "root": paths.root_key.is_file(),
    }


def approve(cfg: Config, admin: str, action_id: str) -> dict[str, Any]:
    """Validate, then run the shared approval code; return its log lines."""
    if admin not in ADMINS:
        raise ConsoleError(f"unknown admin {admin!r}")
    if not ACTION_ID.match(action_id):
        raise ConsoleError("action id must be 12 hex characters")
    lines: list[str] = []
    try:
        result = pki_actions.approve(cfg, admin, action_id, lines.append, identity=IDENTITY)
    except (TrustError, ServiceError) as exc:
        lines.append(f"[admin {admin}] ✗ {exc}")
        raise ConsoleError(str(exc), lines) from exc
    # below threshold `approve` returns the action entry; at threshold, what the root issued
    issued = isinstance(result, dict) and "approvals" not in result
    return {"lines": lines, "issued": issued}


def caller_name(peercert: dict | None) -> str | None:
    """Common name of the verified client certificate."""
    for rdn in (peercert or {}).get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return None


def server_context(cfg: Config) -> ssl.SSLContext:
    tls = client_paths(cfg.tls_dir, IDENTITY)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(tls.ca))
    ctx.load_cert_chain(tls.cert, tls.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_server(cfg: Config, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def _json(self, code: int, data: Any) -> None:
            raw = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _caller(self) -> str | None:
            name = caller_name(self.connection.getpeercert())  # type: ignore[attr-defined]
            if name not in ALLOWED_CALLERS:
                log.info(f"✗ refused caller {name!r} (only {', '.join(sorted(ALLOWED_CALLERS))})")
                self._json(403, {"error": f"caller {name!r} may not use the admin console"})
                return None
            return name

        def do_GET(self) -> None:
            if self._caller() is None:
                return
            if self.path == "/status":
                return self._json(200, key_status(cfg))
            return self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            caller = self._caller()
            if caller is None:
                return
            if self.path != "/approve":
                return self._json(404, {"error": "not found"})
            length = min(int(self.headers.get("Content-Length") or 0), 1024)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
                admin, action_id = str(data["admin"]), str(data["action"])
            except (json.JSONDecodeError, KeyError, TypeError):
                return self._json(400, {"error": "need JSON {admin, action}"})
            log.info(f"{caller} asks admin {admin} to approve {action_id}")
            try:
                return self._json(200, approve(cfg, admin, action_id))
            except ConsoleError as exc:
                lines = exc.args[1] if len(exc.args) > 1 else []
                return self._json(422, {"error": exc.args[0], "lines": lines})

    server = ThreadingHTTPServer((host, port), Handler)
    ctx = server_context(cfg)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def serve(cfg: Config, host: str) -> None:
    keys = key_status(cfg)
    server = make_server(cfg, host, cfg.admin_console_port)
    log.info(
        f"serving on https://{host}:{cfg.admin_console_port} (mTLS; callers: "
        f"{', '.join(sorted(ALLOWED_CALLERS))}); admin keys {', '.join(keys['admins']) or 'none'}, "
        f"root key {'present' if keys['root'] else 'absent'}"
    )
    server.serve_forever()


# --- client --------------------------------------------------------------------------------


class ConsoleClient:
    """What the dashboard uses to reach the console (with its own client cert)."""

    def __init__(self, cfg: Config, identity: str) -> None:
        tls = client_paths(cfg.tls_dir, identity)
        ctx = ssl.create_default_context(cafile=str(tls.ca))
        ctx.load_cert_chain(tls.cert, tls.key)
        self.http = httpx.Client(base_url=cfg.admin_console_url, verify=ctx, timeout=20)
        self._lock = threading.Lock()

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            with self._lock:
                r = self.http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ServiceError(f"admin console unreachable (offline?): {exc}") from exc
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code >= 400:
            raise ConsoleError(data.get("error") or f"HTTP {r.status_code}", data.get("lines", []))
        return data

    def status(self) -> dict[str, Any]:
        return self._call("GET", "/status")

    def approve(self, admin: str, action_id: str) -> dict[str, Any]:
        return self._call("POST", "/approve", json={"admin": admin, "action": action_id})
