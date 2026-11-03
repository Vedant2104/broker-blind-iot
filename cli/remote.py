"""HTTP clients for the evil-broker control API and the device control APIs."""

from __future__ import annotations

from typing import Any

import httpx

from securelib.config import Config

TIMEOUT = 5.0


class RemoteError(RuntimeError):
    pass


class Unreachable(RemoteError):
    pass


def _call(method: str, url: str, **kwargs: Any) -> Any:
    try:
        r = httpx.request(method, url, timeout=TIMEOUT, **kwargs)
    except httpx.HTTPError as exc:
        raise Unreachable(f"cannot reach {url}: {exc}") from exc
    if r.status_code >= 400:
        try:
            detail = r.json().get("error") or r.json().get("detail")
        except ValueError:
            detail = r.text
        raise RemoteError(f"{method} {url} -> {r.status_code}: {detail}")
    return r.json()


# --- evil broker ---------------------------------------------------------------


def proxy_status(cfg: Config) -> dict:
    return _call("GET", f"{cfg.proxy_url}/status")


def proxy_arm(cfg: Config, kind: str, body: dict) -> dict:
    return _call("PUT", f"{cfg.proxy_url}/rules/{kind}", json=body)


def proxy_clear(cfg: Config) -> dict:
    return _call("DELETE", f"{cfg.proxy_url}/rules")


def proxy_captures(
    cfg: Config, topic: str | None = None, seq: int | None = None, limit: int = 50
) -> list[dict]:
    params: dict[str, Any] = {"limit": limit}
    if topic:
        params["topic"] = topic
    if seq is not None:
        params["seq"] = seq
    return _call("GET", f"{cfg.proxy_url}/captures", params=params)


def proxy_inject(cfg: Config, capture_id: int) -> dict:
    return _call("POST", f"{cfg.proxy_url}/inject", json={"capture_id": capture_id})


def proxy_reset(cfg: Config) -> dict:
    return _call("POST", f"{cfg.proxy_url}/reset")


# --- devices ---------------------------------------------------------------------


def device_state(cfg: Config, device: str) -> dict:
    return _call("GET", f"{cfg.device_url(device)}/state")


def device_events(cfg: Config, device: str, after: int = 0) -> list[dict]:
    return _call("GET", f"{cfg.device_url(device)}/events", params={"after": after})


def device_send(cfg: Config, device: str, topic: str, cmd: str, args: dict | None = None) -> dict:
    return _call(
        "POST",
        f"{cfg.device_url(device)}/send",
        json={"topic": topic, "cmd": cmd, "args": args or {}},
    )


def device_reset(cfg: Config, device: str) -> dict:
    return _call("POST", f"{cfg.device_url(device)}/reset")
