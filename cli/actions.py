"""Every user-visible action, shared by the CLI and the dashboard.

Each function takes an ``emit`` callback that receives human-readable log lines
(printed by the CLI, streamed over WebSocket by the dashboard), so a button
click and the equivalent `bbiot` command produce identical output.
"""

from __future__ import annotations

import contextlib
import json
import shlex
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import paho.mqtt.client as mqtt

from cli import remote
from securelib.config import Config
from securelib.mqtt import address, make_client

Emit = Callable[[str], None]

# TLS identity used for HTTPS/MQTT calls made by these actions: "cli" on the
# admin's machine, "dashboard" inside the dashboard container.
IDENTITY = "cli"

SUCCEEDED, BLOCKED, DETECTED = "SUCCEEDED", "BLOCKED", "DETECTED"


@dataclass
class AttackResult:
    attack: str
    outcome: str  # SUCCEEDED | BLOCKED | DETECTED
    reason: str
    command: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _say(emit: Emit, msg: str) -> None:
    emit(f"[attacker] {msg}")


def _cmdline(*parts: str) -> str:
    return "bbiot " + " ".join(shlex.quote(p) for p in parts)


def format_payload(payload: bytes, limit: int = 120) -> str:
    """Readable text if the payload is printable UTF-8, otherwise hex."""
    try:
        text = payload.decode("utf-8")
        if text.isprintable():
            return text if len(text) <= limit else text[:limit] + "…"
    except UnicodeDecodeError:
        pass
    hx = payload.hex(" ")
    return "hex: " + (hx if len(hx) <= limit else hx[:limit] + "…")


def _wait_for(predicate: Callable[[], Any], timeout: float = 5.0, step: float = 0.2) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None


def _events_since(cfg: Config, device: str, mark: int, kind: str | None = None, topic=None):
    return [
        e
        for e in remote.device_events(cfg, device, after=mark)
        if (kind is None or e["kind"] == kind) and (topic is None or e.get("topic") == topic)
    ]


def _rejection(cfg: Config, device: str, mark: int) -> str | None:
    rejected = _events_since(cfg, device, mark, kind="rejected")
    return rejected[-1]["reason"] if rejected else None


def _mark(cfg: Config, device: str) -> int:
    return remote.device_state(cfg, device)["last_event"]


def _cmd_topic(cfg: Config, device: str) -> str:
    return cfg.devices[device].topics["cmd"]


# --- send / spy ----------------------------------------------------------------------


def send(cfg: Config, device: str, topic: str, cmd: str, args: dict, emit: Emit) -> dict:
    sent = remote.device_send(cfg, device, topic, cmd, args)
    emit(f"[{cfg.devices[device].log_name}] → sent {json.dumps(sent['sent'])} to {topic}")
    return sent


class Spy:
    """Subscribe to Mosquitto itself and report everything the broker sees."""

    def __init__(
        self,
        cfg: Config,
        topic_filter: str,
        on_message: Callable[[str, bytes], None],
        identity: str = "cli",
    ):
        self.client = make_client(cfg, identity)
        self.topic_filter = topic_filter
        self.ready = threading.Event()
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = lambda *_a: self.ready.set()
        self.client.on_message = lambda _c, _u, m: on_message(m.topic, m.payload)
        host, port = address(cfg, "mosquitto")
        self.client.connect(host, port, keepalive=30)
        self.client.loop_start()

    def _on_connect(self, client: mqtt.Client, *_a: Any) -> None:
        client.subscribe(self.topic_filter, qos=1)

    def close(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()


def spy_line(topic: str, payload: bytes) -> str:
    return f"[spy] {topic}  {len(payload)}B  {format_payload(payload)}"


# --- attacks 1-5 -------------------------------------------------------------------------


def attack_read(cfg: Config, emit: Emit, seconds: float = 3.0) -> AttackResult:
    """1. Broker reads payloads: listen on home/# while the phone locks the front door."""
    command = _cmdline("attack", "read")
    seen: list[tuple[str, bytes]] = []
    spy = Spy(cfg, "home/#", lambda t, p: seen.append((t, p)))
    try:
        spy.ready.wait(5)
        _say(emit, "listening on home/# as the broker...")
        send(cfg, "phone", _cmd_topic(cfg, "front-door"), "lock", {}, emit)
        time.sleep(seconds)
    finally:
        spy.close()

    readable = []
    for topic, payload in seen:
        emit(spy_line(topic, payload))
        try:
            body = json.loads(payload)
            if isinstance(body, dict):
                readable.append((topic, body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if readable:
        topic, body = next(((t, b) for t, b in readable if "cmd" in b), readable[0])
        fields = {k: v for k, v in body.items() if k not in ("ts",)}
        reason = f"broker read {len(readable)}/{len(seen)} payloads, e.g. {topic} {fields}"
        return AttackResult("read", SUCCEEDED, reason, command, {"seen": len(seen)})
    return AttackResult(
        "read", BLOCKED, f"all {len(seen)} payloads were ciphertext", command, {"seen": len(seen)}
    )


def attack_modify(
    cfg: Config, emit: Emit, setpoint: float = 30.0, requested: float = 21.0
) -> AttackResult:
    """2. Broker rewrites the thermostat setpoint in transit."""
    command = _cmdline("attack", "modify", "--setpoint", f"{setpoint:g}")
    topic = _cmd_topic(cfg, "thermostat")
    remote.proxy_arm(cfg, "modify", {"topic": topic, "setpoint": setpoint})
    _say(emit, f"armed: rewrite setpoint on {topic} to {setpoint:g}")
    mark = _mark(cfg, "thermostat")
    try:
        send(cfg, "phone", topic, "set", {"setpoint": requested}, emit)
        accepted = _wait_for(lambda: _events_since(cfg, "thermostat", mark, "accepted", topic))
        rejected = _rejection(cfg, "thermostat", mark)
    finally:
        remote.proxy_clear(cfg)
    if accepted:
        got = accepted[-1]["body"].get("setpoint")
        if got == setpoint:
            reason = f"phone asked for {requested:g}°C, thermostat accepted {got:g}°C"
            return AttackResult("modify", SUCCEEDED, reason, command)
    if rejected:
        return AttackResult("modify", BLOCKED, f"thermostat rejected: {rejected}", command)
    return AttackResult("modify", BLOCKED, "tampered command was not accepted", command)


def attack_replay(
    cfg: Config, emit: Emit, seq: int | None = None, topic: str | None = None
) -> AttackResult:
    """3. Broker replays a captured 'unlock front door'."""
    topic = topic or _cmd_topic(cfg, "front-door")
    target = cfg.device_for_topic(topic)
    if target is None:
        raise remote.RemoteError(f"no device listens on {topic}")
    command = _cmdline("attack", "replay", *(["--seq", str(seq)] if seq is not None else []))

    if seq is None:
        _say(emit, "waiting for the victim to unlock the door (simulated: phone sends unlock)")
        send(cfg, "phone", topic, "unlock", {}, emit)
        caps = _wait_for(lambda: remote.proxy_captures(cfg, topic=topic, limit=1))
        cap = caps[-1]
    else:
        caps = remote.proxy_captures(cfg, topic=topic, seq=seq, limit=1)
        if not caps:
            known = [c["seq"] for c in remote.proxy_captures(cfg, topic=topic, limit=20)]
            raise remote.RemoteError(f"no captured message with seq {seq} on {topic}: {known}")
        cap = caps[-1]
    _say(emit, f"captured #{cap['id']} on {topic} (seq={cap['seq']}, {cap['size']} bytes)")

    _say(emit, "victim locks the door again")
    send(cfg, "phone", topic, "lock", {}, emit)
    _wait_for(lambda: remote.device_state(cfg, target.id)["state"].get("locked"))

    mark = _mark(cfg, target.id)
    remote.proxy_inject(cfg, cap["id"])
    _say(emit, f"replayed capture #{cap['id']}")
    unlocked = _wait_for(lambda: not remote.device_state(cfg, target.id)["state"].get("locked"))
    rejected = _rejection(cfg, target.id, mark)
    details = {"capture": cap["id"], "seq": cap["seq"]}
    if unlocked:
        reason = f"{target.label} UNLOCKED again by replayed seq {cap['seq']}"
        return AttackResult("replay", SUCCEEDED, reason, command, details)
    why = f"{target.label} rejected: {rejected}" if rejected else "replay had no effect"
    return AttackResult("replay", BLOCKED, why, command, details)


def attack_redirect(cfg: Config, emit: Emit, from_topic: str, to_topic: str) -> AttackResult:
    """4. Broker moves 'unlock front door' onto the back door's topic."""
    command = _cmdline("attack", "redirect", "--from", from_topic, "--to", to_topic)
    victim = cfg.device_for_topic(to_topic)
    if victim is None:
        raise remote.RemoteError(f"no device listens on {to_topic}")

    if victim.kind == "lock":
        send(cfg, "phone", to_topic, "lock", {}, emit)
        _wait_for(lambda: remote.device_state(cfg, victim.id)["state"].get("locked"))

    remote.proxy_arm(cfg, "redirect", {"from_topic": from_topic, "to_topic": to_topic})
    _say(emit, f"armed: redirect {from_topic} -> {to_topic}")
    mark = _mark(cfg, victim.id)
    try:
        send(cfg, "phone", from_topic, "unlock", {}, emit)
        accepted = _wait_for(lambda: _events_since(cfg, victim.id, mark, "accepted", to_topic))
        rejected = _rejection(cfg, victim.id, mark)
    finally:
        remote.proxy_clear(cfg)
    if accepted:
        reason = f"{victim.label} accepted a command the phone sent to {from_topic}"
        return AttackResult("redirect", SUCCEEDED, reason, command)
    why = f"{victim.label} rejected: {rejected}" if rejected else "redirected command ignored"
    return AttackResult("redirect", BLOCKED, why, command)


def attack_drop(cfg: Config, emit: Emit, topic: str, wait: float = 4.0) -> AttackResult:
    """5. Broker silently drops messages on a topic (default: the smoke alarm)."""
    command = _cmdline("attack", "drop", "--topic", topic)
    source = cfg.device_for_topic(topic)
    if source is None:
        raise remote.RemoteError(f"no device publishes on {topic}")

    remote.proxy_arm(cfg, "drop", {"topic": topic})
    _say(emit, f"armed: silently drop everything on {topic}")
    hub_mark = _mark(cfg, "hub") if "hub" in cfg.devices else 0
    phone_mark = _mark(cfg, "phone")
    source_mark = _mark(cfg, source.id)
    try:
        if source.kind == "smoke":
            send(cfg, "phone", source.topics["cmd"], "test", {}, emit)
        sent = _wait_for(lambda: _events_since(cfg, source.id, source_mark, "sent", topic))
        time.sleep(wait)
        received = _events_since(cfg, "phone", phone_mark, "accepted", topic)
    finally:
        remote.proxy_clear(cfg)

    if not sent:
        return AttackResult("drop", BLOCKED, f"{source.label} published nothing", command)
    if received:
        return AttackResult("drop", BLOCKED, "phone still received the message", command)
    # The broker can always drop — the question is whether anyone notices.
    if "hub" in cfg.devices:
        _say(emit, "waiting to see whether the hub notices...")

        def noticed() -> list[dict]:
            return [
                e
                for e in _events_since(cfg, "hub", hub_mark, "alert")
                if source.id in (e.get("title", "") + e.get("reason", ""))
                and e.get("severity") == "critical"
            ]

        alerts = _wait_for(noticed, timeout=15)
        if alerts:
            first = alerts[0]
            ttd = first.get("detect_s")
            how = f" via {first['check']}" if first.get("check") else ""
            when = f" ({ttd:g}s after it was sent)" if isinstance(ttd, int | float) else ""
            reason = f"broker dropped it, but the hub detected it{how}{when}: {first['title']}"
            return AttackResult("drop", DETECTED, reason, command, {"alerts": len(alerts)})
    reason = (
        f"{source.label} published on {topic}, phone never got it and nobody was alerted "
        f"(waited {wait:g}s)"
    )
    return AttackResult("drop", SUCCEEDED, reason, command)


# --- demo -------------------------------------------------------------------------------


def demo_reset(cfg: Config, emit: Emit) -> None:
    remote.proxy_reset(cfg)
    emit("[demo] evil broker: rules and captures cleared")
    release_all(cfg, emit)
    for device in cfg.devices:
        remote.device_reset(cfg, device)
        emit(f"[demo] {device}: reset")


# --- security mode ------------------------------------------------------------------------


def set_security(cfg: Config, mode: str, emit: Emit) -> str:
    """Turn end-to-end protection ON (broker-blind) or OFF (TLS only) on every device."""
    if mode not in ("on", "off"):
        raise remote.RemoteError("mode must be on or off")
    for device in cfg.devices:
        try:
            remote.device_set_security(cfg, device, mode)
            emit(f"[{cfg.devices[device].log_name}] security {mode.upper()}")
        except remote.Unreachable:
            emit(f"[{cfg.devices[device].log_name}] unreachable — skipped")
    label = "broker-blind (AEAD + signatures)" if mode == "on" else "TLS only (broker reads all)"
    emit(f"[demo] security {mode.upper()}: {label}")
    return mode


def security_mode(cfg: Config) -> str:
    modes = set()
    for device in cfg.devices:
        with contextlib.suppress(remote.RemoteError):
            modes.add(remote.device_state(cfg, device)["security"])
    return modes.pop() if len(modes) == 1 else "mixed" if modes else "unknown"


# --- attack 6 ---------------------------------------------------------------------------------


def attack_mitm_dh(
    cfg: Config, emit: Emit, unsigned: bool = False, victim: str = "thermostat"
) -> AttackResult:
    """6. Broker MITMs the device <-> KDC key exchange."""
    auth = "unsigned" if unsigned else "signed"
    command = _cmdline("attack", "mitm-dh", *(["--unsigned"] if unsigned else []))
    remote.proxy_arm_mitm(cfg, victim)
    _say(emit, f"armed: man-in-the-middle on {victim}'s key exchange with the KDC")
    if unsigned:
        remote.kdc_allow_unsigned(cfg, victim)
        _say(emit, "KDC told to accept one UNSIGNED exchange (the insecure design)")
    mark = _mark(cfg, victim)
    stolen, proof, alert = None, None, None
    try:
        remote.device_rejoin(cfg, victim, auth)
        _say(emit, f"{victim} re-joins the group ({auth} X25519 key exchange via the broker)")
        if unsigned:
            stolen = _wait_for(
                lambda: remote.proxy_mitm_status(cfg)["stolen_epochs"].get(victim), timeout=8
            )
            if stolen:
                _say(
                    emit, f"swapped both DH shares; unwrapped the group key for epoch {stolen[-1]}"
                )
                # Make some traffic under that key, then decrypt it.
                send(cfg, "phone", _cmd_topic(cfg, "thermostat"), "set", {"setpoint": 21}, emit)
                time.sleep(1.5)
                try:
                    proof = remote.proxy_mitm_decrypt(cfg)
                except remote.RemoteError:
                    proof = None
        alert = _wait_for(lambda: _events_since(cfg, victim, mark, "alert"), timeout=5)
    finally:
        remote.proxy_clear(cfg)

    if unsigned and stolen:
        what = (
            f"; decrypted {proof['topic']} from {proof['sender']} (fields: "
            f"{', '.join(proof['fields'])})"
            if proof
            else ""
        )
        reason = f"broker stole the epoch-{stolen[-1]} group key via unsigned DH{what}"
        _say(emit, "evicting the attacker: KDC rekeys, victim re-joins with a signed exchange")
        remote.kdc_rekey(cfg)
        remote.device_rejoin(cfg, victim, "signed")
        return AttackResult("mitm-dh", SUCCEEDED, reason, command, {"epoch": stolen[-1]})
    if alert:
        _say(emit, f"{victim} retries with a clean signed exchange")
        remote.device_rejoin(cfg, victim, "signed")
        return AttackResult("mitm-dh", BLOCKED, alert[-1]["reason"], command)
    return AttackResult("mitm-dh", BLOCKED, "key exchange could not be tampered with", command)


# --- key mode -----------------------------------------------------------------------------------

KEYMODES = ("centralized", "decentralized")


def set_keymode(cfg: Config, keymode: str, emit: Emit, wait: float = 20.0) -> str:
    """Switch every device between the KDC (centralized) and MLS (decentralized)."""
    if keymode not in KEYMODES:
        raise remote.RemoteError(f"key mode must be one of {', '.join(KEYMODES)}")
    for device in cfg.devices:
        try:
            remote.device_set_keymode(cfg, device, keymode)
            emit(f"[{cfg.devices[device].log_name}] key mode {keymode.upper()}")
        except remote.RemoteError as exc:
            emit(f"[{cfg.devices[device].log_name}] skipped: {exc}")

    def ready() -> list[str]:
        return [
            d
            for d in cfg.devices
            if (remote.device_state(cfg, d).get("group") or {}).get("epoch") is None
            and remote.device_state(cfg, d)["identity"]["cert"]["status"] == "trusted"
        ]

    waiting = _wait_for(lambda: not ready(), timeout=wait)
    if waiting is None:
        emit(f"[demo] still waiting for a {keymode} group key on: {', '.join(ready())}")
    who = "KDC knows the group key" if keymode == "centralized" else "nobody but members knows it"
    emit(f"[demo] key mode {keymode.upper()} ({who})")
    return keymode


def keymode_now(cfg: Config) -> str:
    modes = set()
    for device in cfg.devices:
        with contextlib.suppress(remote.RemoteError):
            modes.add(remote.device_state(cfg, device).get("keymode"))
    modes.discard(None)
    return modes.pop() if len(modes) == 1 else "mixed" if modes else "unknown"


# --- attack 9 -------------------------------------------------------------------------------------


def attack_swap_key(cfg: Config, emit: Emit, device: str = "thermostat") -> AttackResult:
    """9. Compromised directory substitutes a device's public key."""
    from securelib.services import DirectoryClient
    from securelib.trust import TrustAnchors

    command = _cmdline("attack", "swap-key", "--device", device)
    keymode, security = keymode_now(cfg), security_mode(cfg)
    directory = DirectoryClient.connect(cfg, IDENTITY)
    what = "keypackage" if keymode == "decentralized" else "cert"
    directory.evil_swap(device, what)
    _say(emit, f"directory compromised: serving the attacker's {what} for {device}")
    marks = {d: _mark(cfg, d) for d in cfg.devices}
    try:
        if security == "off":
            # A client that trusts the directory blindly (no root/log/pin checks).
            served = directory.get_cert(device)
            from cryptography import x509 as _x509

            from securelib.pki import fingerprint, raw_public

            pub = _x509.load_pem_x509_certificate(served["cert_pem"].encode()).public_key()
            fp = fingerprint(raw_public(pub))
            reason = (
                f"a client without verification would trust the directory's key for "
                f"{device} (fp {fp[:23]}…) — the attacker's"
            )
            return AttackResult("swap-key", SUCCEEDED, reason, command)

        if keymode == "decentralized":
            _say(emit, f"{device} asks the MLS admin ({cfg.group_admin}) to re-add it")
            remote.device_mls_rejoin(cfg, device)
        else:
            _say(emit, f"{device} re-joins via the KDC; every device re-checks its certificate")
            remote.device_rejoin(cfg, device)

        def caught() -> list[dict]:
            return [
                {**e, "device": d}
                for d in cfg.devices
                for e in _events_since(cfg, d, marks[d], "alert")
            ]

        alerts = _wait_for(caught, timeout=20)
        # Independent check from the CLI's own verifier.
        anchors = TrustAnchors.from_config(cfg)
        try:
            anchors.verify_cert_pem(directory.get_cert(device)["cert_pem"], expected_id=device)
            cli_view = "certificate itself is genuine"
        except Exception as exc:  # noqa: BLE001 - any trust failure is the evidence
            cli_view = f"CLI check: {exc}"
    finally:
        directory.evil_clear()
        _say(emit, "directory restored; the victim re-joins with its genuine keys")
        with contextlib.suppress(remote.RemoteError):
            if keymode == "decentralized":
                remote.device_mls_rejoin(cfg, device)
            else:
                remote.device_rejoin(cfg, device)

    if alerts:
        first = alerts[0]
        reason = f"caught by {first['device']}: {first['reason']} ({cli_view})"
        return AttackResult("swap-key", BLOCKED, reason, command, {"alerts": len(alerts)})
    return AttackResult("swap-key", BLOCKED, f"substituted key never used ({cli_view})", command)


# --- attack 10 ------------------------------------------------------------------------------------


def _hex_candidates(obj, out: set[str]) -> None:
    """Every 32-byte value that appears anywhere in a JSON dump (as hex)."""
    if isinstance(obj, dict):
        for v in obj.values():
            _hex_candidates(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _hex_candidates(v, out)
    elif isinstance(obj, str) and len(obj) >= 64:
        try:
            bytes.fromhex(obj)
        except ValueError:
            return
        for i in range(0, len(obj) - 63, 64):
            out.add(obj[i : i + 64])


def attack_kdc_vs_directory(cfg: Config, emit: Emit) -> AttackResult:
    """10. Compromised KDC (centralized) vs. compromised directory (decentralized)."""
    from securelib.services import DirectoryClient

    command = _cmdline("attack", "kdc-vs-directory")
    keymode = keymode_now(cfg)
    latest = remote.proxy_captures(cfg, limit=1)
    since = latest[-1]["id"] if latest else 0  # judge only traffic sent during this attack
    _say(emit, f"key mode is {keymode.upper()}; generating traffic to steal")
    send(cfg, "phone", _cmd_topic(cfg, "thermostat"), "set", {"setpoint": 21}, emit)
    time.sleep(1.5)

    leaked = remote.kdc_leak(cfg)
    _say(emit, f"KDC compromised: it hands over its epoch-{leaked['leaked_epoch']} group key")
    dump = DirectoryClient.connect(cfg, IDENTITY).evil_dump()
    cands: set[str] = set()
    _hex_candidates(dump, cands)
    n_kp = len(dump.get("key_packages", {}))
    n_hs = len(dump.get("handshakes", []))
    _say(
        emit,
        f"directory compromised: dumped {len(dump.get('certs', {}))} certificates, {n_kp} key "
        f"packages, {n_hs} MLS handshakes → {len(cands)} candidate 32-byte values",
    )
    result = remote.proxy_try_loot(cfg, sorted(cands), after_capture=since)
    if result["messages"] == 0:
        return AttackResult(
            "kdc-vs-directory", BLOCKED, f"{keymode}: no sealed traffic to attack", command
        )
    if result["decrypted"]:
        reason = (
            f"{keymode}: compromised KDC's key decrypted {result['topic']} from "
            f"{result['sender']} (fields: {', '.join(result['fields'])}) — the KDC reads everything"
        )
        return AttackResult("kdc-vs-directory", SUCCEEDED, reason, command, result)
    reason = (
        f"{keymode}: neither the KDC's key nor anything in the directory "
        f"({len(cands)} candidates) decrypts the {result['messages']} sealed messages — "
        "MLS secrets exist only on member devices"
    )
    return AttackResult("kdc-vs-directory", BLOCKED, reason, command, result)


# --- quarantine ----------------------------------------------------------------------------------


def release_all(cfg: Config, emit: Emit) -> None:
    if "hub" not in cfg.devices:
        return
    with contextlib.suppress(remote.RemoteError):
        for ident in list(remote.hub_state(cfg).get("quarantined", {})):
            remote.hub_release(cfg, ident)
            emit(f"[hub] released {ident} from quarantine")


# --- attack 7 ------------------------------------------------------------------------------------


def attack_compromised_device(cfg: Config, emit: Emit, device: str = "thermostat") -> AttackResult:
    """7. A compromised device (holding valid keys) subscribes to the door topics."""
    command = _cmdline("attack", "compromised-device", "--device", device)
    doors = sorted(d.topics["cmd"] for d in cfg.devices.values() if d.kind == "lock")[:2]
    security = security_mode(cfg)
    mark, hub_mark = _mark(cfg, device), _mark(cfg, "hub")
    before = remote.device_state(cfg, device)["group"].get("epoch")
    try:
        remote.device_compromise(cfg, device, doors)
        _say(emit, f"{device} is compromised: it subscribes to {', '.join(doors)}")
        send(cfg, "phone", doors[0], "unlock", {}, emit)
        time.sleep(2.5)
        spied = _events_since(cfg, device, mark, "spied")
        if security == "off":
            if spied:
                body = spied[0].get("body", {})
                reason = f"{device} read {len(spied)} door command(s), e.g. {body} — nobody noticed"
                return AttackResult("compromised-device", SUCCEEDED, reason, command)
            return AttackResult("compromised-device", BLOCKED, "nothing was read", command)

        alerts = _wait_for(
            lambda: [
                e
                for e in _events_since(cfg, "hub", hub_mark, "alert")
                if e.get("title", "").startswith("QUARANTINED")
            ],
            timeout=8,
        )
        if not alerts:
            why = f"read {len(spied)} message(s)" if spied else "no quarantine raised"
            return AttackResult("compromised-device", SUCCEEDED, why, command)
        _say(emit, f"hub: {alerts[0]['title']} — {alerts[0]['reason']}")

        def rekeyed() -> int | None:
            st = remote.device_state(cfg, "phone")["group"]
            return st.get("epoch") if st.get("epoch") not in (None, before) else None

        new_epoch = _wait_for(rekeyed, timeout=15)
        _say(emit, f"group rekeyed: epoch {before} → {new_epoch}")
        send(cfg, "phone", doors[0], "lock", {}, emit)
        time.sleep(1.5)
        cap = remote.proxy_captures_with_payload(cfg, doors[0], limit=1)
        proof = (
            remote.device_try_decrypt(cfg, device, doors[0], cap[-1]["payload"])
            if cap
            else {"ok": False, "reason": "no capture"}
        )
        if proof.get("ok"):
            reason = f"{device} was quarantined but can still decrypt new door commands"
            return AttackResult("compromised-device", SUCCEEDED, reason, command)
        reason = (
            f"hub blocked the subscription and quarantined {device} "
            f"({len(spied)} commands read); rekey {before} → {new_epoch}; "
            f"newest door command: {proof['reason']}"
        )
        return AttackResult(
            "compromised-device",
            BLOCKED,
            reason,
            command,
            {"spied": len(spied), "epoch_before": before, "epoch_after": new_epoch},
        )
    finally:
        with contextlib.suppress(remote.RemoteError):
            remote.hub_release(cfg, device)
            remote.device_reset(cfg, device)
        _say(emit, f"cleanup: {device} restored and released from quarantine")


# --- attack 8 ------------------------------------------------------------------------------------


def _try_connect(cfg: Config, host: str, port: int, ctx) -> str:
    """Connect with a given TLS context; return 'connected' or the failure."""
    import paho.mqtt.client as _mqtt

    done, result = threading.Event(), {}
    c = _mqtt.Client(callback_api_version=_mqtt.CallbackAPIVersion.VERSION2)
    c.tls_set_context(ctx)
    c.on_connect = lambda *a: (result.setdefault("rc", a[3]), done.set())
    try:
        c.connect(host, port, keepalive=10)
    except OSError as exc:
        return f"refused during TLS handshake ({type(exc).__name__})"
    c.loop_start()
    done.wait(4)
    c.disconnect()
    c.loop_stop()
    rc = result.get("rc")
    return "connected" if rc is not None and not rc.is_failure else "refused (no CONNACK)"


def attack_counterfeit(cfg: Config, emit: Emit, target: str = "front-door") -> AttackResult:
    """8. A counterfeit device (no certificate from the bbiot root) tries to get in."""
    import ssl
    import tempfile
    from pathlib import Path

    from securelib.kdcproto import DeviceJoin
    from securelib.mqtt import tls_context
    from securelib.tls import client_paths, init_tls

    command = _cmdline("attack", "counterfeit")
    security = security_mode(cfg)
    door = cfg.devices[target].topics["cmd"]
    stages: list[str] = []
    send(cfg, "phone", door, "lock", {}, emit)
    _wait_for(lambda: remote.device_state(cfg, target)["state"].get("locked"))
    mark = _mark(cfg, target)

    def stage(msg: str) -> None:
        stages.append(msg)
        _say(emit, msg)

    # 1. no certificate at all; 2. certificate from its own CA
    stage(
        "① no client certificate → "
        + _try_connect(
            cfg, cfg.broker_host, cfg.broker_port, tls_context(cfg, IDENTITY, client_cert=False)
        )
    )
    with tempfile.TemporaryDirectory() as tmp:
        init_tls(Path(tmp), [target])
        rogue = client_paths(Path(tmp), target)
        ctx = ssl.create_default_context(cafile=str(client_paths(cfg.tls_dir, IDENTITY).ca))
        ctx.load_cert_chain(rogue.cert, rogue.key)
        stage(
            f"② self-made certificate claiming '{target}' → "
            + _try_connect(cfg, cfg.broker_host, cfg.broker_port, ctx)
        )

    # 3/4. a stolen *transport* identity ('counterfeit'), but no device certificate
    def plaintext_unlock(host: str, port: int) -> None:
        c = make_client(cfg, "counterfeit")
        c.connect(host, port, keepalive=10)
        c.loop_start()
        time.sleep(0.5)
        c.publish(door, json.dumps({"from": "phone", "seq": 1, "cmd": "unlock"}), qos=1)
        time.sleep(1.5)
        c.disconnect()
        c.loop_stop()

    hub_mark = _mark(cfg, "hub") if "hub" in cfg.devices else 0
    plaintext_unlock(cfg.broker_host, cfg.broker_port)
    blocked = [
        e
        for e in _events_since(cfg, "hub", hub_mark, "alert")
        if "counterfeit" in e.get("title", "")
    ]
    stage(
        "③ transport cert via the hub, forged 'unlock' → "
        + ("hub blocked + quarantined it (no MUD profile)" if blocked else "passed the hub")
    )

    plaintext_unlock(cfg.evil_host, cfg.evil_port)
    rej = _rejection(cfg, target, mark)
    unlocked = not remote.device_state(cfg, target)["state"].get("locked")
    stage(
        "④ bypassing the hub, straight to the broker → "
        + ("door UNLOCKED" if unlocked else f"{target} rejected it: {rej or 'ignored'}")
    )

    if security == "on":  # impersonate the target in a KDC join (it has no device key)
        from securelib.trust import TrustAnchors

        got = threading.Event()
        c = make_client(cfg, "counterfeit")
        join = DeviceJoin(target)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        fake_key, kdc_key = Ed25519PrivateKey.generate(), TrustAnchors.from_config(cfg).kdc_key

        def on_msg(_c, _u, m) -> None:
            msg = json.loads(m.payload)
            if m.topic.endswith(f"session/{target}") and msg.get("t") == "challenge":
                try:
                    finish, _ = join.on_challenge(msg, kdc_key, fake_key)
                    _c.publish(f"kdc/join/{target}", json.dumps(finish), qos=1)
                except Exception:  # noqa: BLE001,S110 - a mismatched challenge is fine too
                    pass
            elif m.topic.endswith(f"key/{target}"):
                got.set()

        c.on_message = on_msg
        c.connect(cfg.evil_host, cfg.evil_port, keepalive=10)
        c.loop_start()
        c.subscribe([(f"kdc/session/{target}", 1), (f"kdc/key/{target}", 1)])
        time.sleep(0.5)
        c.publish(f"kdc/join/{target}", json.dumps(join.hello()), qos=1)
        got.wait(4)
        c.disconnect()
        c.loop_stop()
        stage(
            f"⑤ impersonating {target} in a KDC join → "
            + ("GOT a group key" if got.is_set() else "KDC refused (signature ≠ certified key)")
        )

    release_all(cfg, lambda _l: None)
    if unlocked:
        return AttackResult(
            "counterfeit",
            SUCCEEDED,
            f"counterfeit unlocked the {target}",
            command,
            {"stages": stages},
        )
    return AttackResult(
        "counterfeit", BLOCKED, "; ".join(s[2:] for s in stages), command, {"stages": stages}
    )
