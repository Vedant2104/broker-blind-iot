"""PKI workflows shared by the CLI (and later the dashboard): init, pairing,
admin approvals, root issuing, bootstrap and log verification.

Commands that touch offline keys (init, approve, issue) run on the admin's
machine — the host — never inside the running system's containers.
"""

from __future__ import annotations

import time
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from cli import remote
from cli.actions import Emit
from rootca import approvals
from rootca.root import (
    PkiPaths,
    init_pki,
    issue_device_cert,
    issue_revocation,
    load_admin_key,
    load_roster,
)
from securelib.config import Config
from securelib.pki import TrustError, pairing_code, raw_public, read_x25519_extension
from securelib.services import DirectoryClient, ServiceError
from securelib.trust import KeyChanged, PeerVerifier, TrustAnchors

CLI_IDENTITY = "cli"


def pki_paths(cfg: Config) -> PkiPaths:
    return PkiPaths(cfg.offline_dir, cfg.pki_public_dir, cfg.translog_key_path)


def directory(cfg: Config, identity: str = CLI_IDENTITY) -> DirectoryClient:
    return DirectoryClient.connect(cfg, identity)


# --- setup ---------------------------------------------------------------------------------


def pki_init(cfg: Config, emit: Emit, *, force: bool = False) -> None:
    notes = init_pki(pki_paths(cfg), force=force)
    if not notes:
        emit(f"[rootca] PKI already initialised ({cfg.offline_dir.as_posix()}), keeping it")
        return
    for note in notes:
        emit(f"[rootca] {note}")
    emit(f"[rootca] public trust anchors -> {cfg.pki_public_dir.as_posix()}")


# --- pairing -------------------------------------------------------------------------------


def inspect_csr(csr_pem: bytes, device_id: str) -> str:
    """Check the CSR's proof of possession and identity; return the pairing code
    computed independently from its public keys."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise TrustError("CSR proof-of-possession signature invalid")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != device_id:
        raise TrustError(f"CSR is for {cn[0].value if cn else '?'}, not {device_id}")
    pub = csr.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        raise TrustError("CSR key is not Ed25519")
    return pairing_code(raw_public(pub), raw_public(read_x25519_extension(csr.extensions)))


def pair(cfg: Config, device: str, emit: Emit, *, identity: str = CLI_IDENTITY) -> str:
    """Steps 1-3 of pairing: find the device, verify its request, show the code
    to compare, post the add-device action for admin approval."""
    emit(f"[pair] ① device found: {device} (local pairing channel)")
    info = remote.device_identity(cfg, device)
    csr_pem = info["csr_pem"].encode()
    code = inspect_csr(csr_pem, device)
    emit("[pair] ② signing request verified: Ed25519 proof of possession ✓, CN matches ✓")
    emit(f"[pair] ③ pairing code from the request: {code}")
    emit(f"[pair]    pairing code on the device:    {info['pairing_code']}")
    if code != info["pairing_code"]:
        raise TrustError("pairing codes DIFFER — the request was swapped in transit; aborting")
    emit("[pair]    ✓ codes match (in real life: compare with the QR code on the device)")
    _refuse_second_cert(cfg, device, info["fingerprint"], identity)

    action = approvals.new_action("add-device", device, csr_pem)
    posted = directory(cfg, identity).post_action(action, csr_pem.decode())
    aid = posted["id"]
    emit(f"[pair] ④ action {aid}: add-device {device} — needs 2 of 3 admin approvals")
    emit(f"[pair]    next: bbiot admin approve --admin A --action {aid}")
    return aid


def _refuse_second_cert(cfg: Config, device: str, fingerprint: str, identity: str) -> None:
    """One live certificate per device key. A second one would survive revocation of the
    first (revocations are by serial), so a commissioned device must be revoked first."""
    current = directory(cfg, identity).get_cert(device)
    if current is None or current.get("fingerprint") != fingerprint:
        return
    serial = x509.load_pem_x509_certificate(current["cert_pem"].encode()).serial_number
    anchors = TrustAnchors.from_config(cfg)
    revoked = anchors.revoked(directory(cfg, identity).list_revocations())
    if serial not in revoked.get(device, set()):
        raise TrustError(
            f"{device} is already commissioned with these keys (log leaf "
            f"#{current.get('leaf_index')}); revoke it first: bbiot revoke --device {device}"
        )


def approve(
    cfg: Config,
    admin: str,
    action_id: str,
    emit: Emit,
    *,
    auto_issue: bool = True,
    identity: str = CLI_IDENTITY,
):
    d = directory(cfg, identity)
    entry = d.get_action(action_id)
    if entry is None:
        raise ServiceError(f"no pending action {action_id}")
    action = entry["action"]
    roster = load_roster(pki_paths(cfg))
    emit(f"[admin {admin}] reviewing {action_id}: {action['type']} {action['device_id']}")
    approvals.check_fresh(action)  # don't sign something nobody can still use
    if action["type"] == "add-device":
        code = inspect_csr(entry["csr_pem"].encode(), action["device_id"])
        emit(f"[admin {admin}] device pairing code {code}")
    sig = approvals.sign_approval(load_admin_key(pki_paths(cfg), admin), action)
    updated = d.approve(action_id, admin, sig)
    approvers = approvals.valid_approvers(action, updated["approvals"], roster)
    need = roster["threshold"]
    emit(f"[admin {admin}] ✓ signed — approvals {len(approvers)}/{need} ({', '.join(approvers)})")
    if len(approvers) >= need and updated["status"] == "pending" and auto_issue:
        return issue(cfg, action_id, emit, identity=identity)
    if len(approvers) < need:
        others = [a for a in approvals.ADMINS if a not in approvers]
        emit(
            f"[admin {admin}] waiting for one more: bbiot admin approve --admin {others[0]} "
            f"--action {action_id}"
        )
    return updated


def revoke(cfg: Config, device: str, emit: Emit, *, identity: str = CLI_IDENTITY) -> str:
    """Post a remove-device action; at 2 of 3 approvals the root signs the revocation,
    the KDC drops the device and rekeys."""
    if directory(cfg, identity).get_cert(device) is None:
        raise ServiceError(f"{device} has no certificate to revoke")
    action = approvals.new_action("remove-device", device)
    aid = directory(cfg, identity).post_action(action, None)["id"]
    emit(f"[revoke] action {aid}: remove-device {device} — needs 2 of 3 admin approvals")
    emit(f"[revoke]    next: bbiot admin approve --admin A --action {aid}")
    return aid


def issue(
    cfg: Config, action_id: str, emit: Emit, *, identity: str = CLI_IDENTITY
) -> dict[str, Any]:
    d = directory(cfg, identity)
    entry = d.get_action(action_id)
    if entry is None:
        raise ServiceError(f"no action {action_id}")
    if entry["action"]["type"] == "remove-device":
        return _issue_revocation(cfg, entry, emit, identity)
    pem, approvers = issue_device_cert(
        pki_paths(cfg), entry["action"], entry["csr_pem"].encode(), entry["approvals"]
    )
    cert = x509.load_pem_x509_certificate(pem)
    device = entry["action"]["device_id"]
    serial = f"{cert.serial_number:x}"[:16]
    emit(
        f"[rootca] ⑤ threshold met ({' + '.join(approvers)}) → offline root signed "
        f"certificate for {device} (serial {serial}…)"
    )
    published = d.publish(pem.decode(), action_id)
    emit(
        f"[directory] ⑥ published {device}; transparency log leaf #{published['leaf_index']}, "
        f"tree size {published['sth']['tree_size']}"
    )
    emit(f"[pair] ✓ {device} commissioned — it will pick up its certificate within seconds")
    return published


def _issue_revocation(cfg: Config, entry: dict, emit: Emit, identity: str) -> dict[str, Any]:
    d = directory(cfg, identity)
    device = entry["action"]["device_id"]
    current = d.get_cert(device)
    if current is None:
        raise ServiceError(f"{device} has no certificate")
    serial = format(x509.load_pem_x509_certificate(current["cert_pem"].encode()).serial_number, "x")
    signed, approvers = issue_revocation(
        pki_paths(cfg), entry["action"], entry["approvals"], serial
    )
    emit(
        f"[rootca] threshold met ({' + '.join(approvers)}) → offline root signed the "
        f"revocation of {device} (serial {serial[:16]}…)"
    )
    d.publish_revocation(signed)
    emit(f"[directory] revocation of {device} published; the KDC will drop it and rekey")
    return signed


def bootstrap(cfg: Config, emit: Emit, wait: float = 60.0) -> None:
    """Commission every device marked commissioned: true (setup ceremony, admins A + B)."""
    d = directory(cfg)
    deadline = time.monotonic() + wait
    while True:  # the directory may still be starting
        try:
            d.list_certs()
            break
        except ServiceError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)
    for dev in cfg.devices.values():
        if not dev.commissioned:
            emit(f"[bootstrap] {dev.id}: left for live pairing (bbiot pair --device {dev.id})")
            continue
        info = _wait_for_identity(cfg, dev.id, wait)
        current = d.get_cert(dev.id)
        if current and current.get("fingerprint") == info["fingerprint"]:
            emit(f"[bootstrap] {dev.id}: already commissioned, skipping")
            continue
        aid = pair(cfg, dev.id, emit)
        approve(cfg, "A", aid, emit, auto_issue=False)
        approve(cfg, "B", aid, emit)


def _wait_for_identity(cfg: Config, device: str, wait: float) -> dict:
    deadline = time.monotonic() + wait
    while True:
        try:
            return remote.device_identity(cfg, device)
        except remote.RemoteError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


# --- verification ----------------------------------------------------------------------------


def log_verify(cfg: Config, emit: Emit, identity: str = CLI_IDENTITY) -> bool:
    """Verify the log: STH signature, consistency with the last STH this
    machine saw, inclusion of every certificate the directory serves, pins."""
    verifier = PeerVerifier.for_identity(cfg, identity, cfg.state_dir / identity)
    sth, prev = verifier.log.fresh_sth()
    emit(
        f"[translog] signed tree head: size {sth.tree_size}, root {sth.root_hash.hex()[:16]}… "
        "signature ✓ (log key certified by root)"
    )
    if prev is None:
        emit("[translog] first tree head seen on this machine — remembered for next time")
    else:
        emit(
            f"[translog] consistent with the tree head seen before (size {prev.tree_size} → "
            f"{sth.tree_size}) ✓"
        )
    ok = True
    entries = verifier.directory.list_certs()
    for entry in sorted(entries, key=lambda e: e["leaf_index"]):
        dev = entry["device_id"]
        try:
            peer = verifier.verify(dev, entry)
            if peer.leaf_index != entry["leaf_index"]:
                raise TrustError(
                    f"directory claims leaf #{entry['leaf_index']}, log says #{peer.leaf_index}"
                )
            emit(
                f"[translog] ✓ {dev:<14} root ✓  leaf #{peer.leaf_index} included ✓  "
                f"pin: {peer.pin}  fp {peer.identity.fingerprint[:23]}…"
            )
        except KeyChanged as exc:
            ok = False
            emit(f"[translog] ✗ {dev:<14} {exc}")
        except TrustError as exc:
            ok = False
            emit(f"[translog] ✗ {dev:<14} {exc}")
    emit(f"[translog] {'all' if ok else 'NOT all'} {len(entries)} directory entries verified")
    return ok


def keys_table(cfg: Config, emit: Emit) -> None:
    entries = {e["device_id"]: e for e in directory(cfg).list_certs()}
    for dev in cfg.devices:
        e = entries.get(dev)
        if e is None:
            emit(f"[keys] {dev:<14} no certificate")
        else:
            emit(f"[keys] {dev:<14} leaf #{e['leaf_index']:<3} fp {e['fingerprint']}")
