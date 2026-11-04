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


def device_identity(cfg: Config, device: str) -> dict:
    """The device's public identity: CSR, pairing code, fingerprint, cert status."""
    return _call("GET", f"{cfg.device_url(device)}/identity")


def device_set_security(cfg: Config, device: str, mode: str) -> dict:
    return _call("POST", f"{cfg.device_url(device)}/security", json={"mode": mode})


def device_rejoin(cfg: Config, device: str, auth: str = "signed") -> dict:
    return _call("POST", f"{cfg.device_url(device)}/rejoin", json={"auth": auth})


def kdc_status(cfg: Config) -> dict:
    return _call("GET", f"{cfg.kdc_url}/status")


def kdc_rekey(cfg: Config) -> dict:
    return _call("POST", f"{cfg.kdc_url}/rekey")


def kdc_allow_unsigned(cfg: Config, device: str) -> dict:
    return _call("POST", f"{cfg.kdc_url}/allow-unsigned", json={"device": device})


def proxy_arm_mitm(cfg: Config, device: str) -> dict:
    return _call("PUT", f"{cfg.proxy_url}/rules/mitm-dh", json={"device": device})


def proxy_mitm_status(cfg: Config) -> dict:
    return _call("GET", f"{cfg.proxy_url}/mitm")


def proxy_mitm_decrypt(cfg: Config) -> dict:
    return _call("POST", f"{cfg.proxy_url}/mitm/decrypt")


def device_set_keymode(cfg: Config, device: str, keymode: str) -> dict:
    return _call("POST", f"{cfg.device_url(device)}/keymode", json={"keymode": keymode})


def device_mls_rejoin(cfg: Config, device: str) -> dict:
    return _call("POST", f"{cfg.device_url(device)}/mls-rejoin")


def kdc_leak(cfg: Config) -> dict:
    return _call("POST", f"{cfg.kdc_url}/evil/leak")


def proxy_try_loot(cfg: Config, candidates: list[str], after_capture: int = 0) -> dict:
    body = {"candidates": candidates, "after_capture": after_capture}
    return _call("POST", f"{cfg.proxy_url}/loot/try", json=body)


def proxy_captures_with_payload(cfg: Config, topic: str, limit: int = 1) -> list[dict]:
    params = {"topic": topic, "limit": limit, "with_payload": True}
    return _call("GET", f"{cfg.proxy_url}/captures", params=params)


def hub_state(cfg: Config) -> dict:
    return device_state(cfg, "hub")["state"]


def hub_release(cfg: Config, ident: str) -> dict:
    return _call("POST", f"{cfg.device_url('hub')}/release", json={"device": ident})


def device_compromise(cfg: Config, device: str, topics: list[str]) -> dict:
    return _call("POST", f"{cfg.device_url(device)}/compromise", json={"subscribe": topics})


def device_try_decrypt(cfg: Config, device: str, topic: str, payload_hex: str) -> dict:
    body = {"topic": topic, "payload": payload_hex}
    return _call("POST", f"{cfg.device_url(device)}/try-decrypt", json=body)


# --- log tails (Terminal page) ------------------------------------------------------------


def device_logs(cfg: Config, device: str, after: int = 0) -> list[dict]:
    return _call("GET", f"{cfg.device_url(device)}/logs", params={"after": after})


def proxy_logs(cfg: Config, after: int = 0) -> list[dict]:
    return _call("GET", f"{cfg.proxy_url}/logs", params={"after": after})


def kdc_logs(cfg: Config, after: int = 0) -> list[dict]:
    return _call("GET", f"{cfg.kdc_url}/logs", params={"after": after})
