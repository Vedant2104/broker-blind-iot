"""Root, admin approvals, certificate issuing and verification — including
every way an attacker might try to get a bad certificate accepted."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rootca import approvals
from rootca.root import PkiPaths, init_pki, issue_device_cert, load_admin_key, load_roster
from securelib.identity import DeviceKeys, build_csr, read_private
from securelib.pki import (
    TreeHead,
    TrustError,
    load_root,
    sth_message,
    verify_device_cert,
    verify_service_cert,
    verify_sth,
)


@pytest.fixture
def pki(tmp_path: Path) -> PkiPaths:
    paths = PkiPaths(tmp_path / "offline", tmp_path / "public", tmp_path / "translog" / "log.key")
    init_pki(paths)
    return paths


@pytest.fixture
def device(tmp_path: Path) -> DeviceKeys:
    keys, created = DeviceKeys.load_or_create(tmp_path / "dev" / "garage-lock", "garage-lock")
    assert created
    return keys


def approve(pki: PkiPaths, action: dict, *admins: str) -> dict[str, str]:
    return {a: approvals.sign_approval(load_admin_key(pki, a), action) for a in admins}


def issue(pki: PkiPaths, device: DeviceKeys, *admins: str) -> x509.Certificate:
    admins = admins or ("A", "B")
    action = approvals.new_action("add-device", device.device_id, device.csr_pem)
    pem, _ = issue_device_cert(pki, action, device.csr_pem, approve(pki, action, *admins))
    return x509.load_pem_x509_certificate(pem)


def root(pki: PkiPaths):
    return load_root(pki.root_crt.read_bytes())


# --- setup ------------------------------------------------------------------------------------


def test_init_is_idempotent(pki: PkiPaths) -> None:
    before = pki.root_crt.read_bytes()
    assert init_pki(pki) == []
    assert pki.root_crt.read_bytes() == before


def test_roster_signed_by_root(pki: PkiPaths) -> None:
    roster = load_roster(pki)
    assert roster["threshold"] == 2 and set(roster["admins"]) == {"A", "B", "C"}


def test_tampered_roster_rejected(pki: PkiPaths) -> None:
    signed = json.loads(pki.roster.read_text())
    signed["roster"]["admins"]["D"] = signed["roster"]["admins"]["A"]
    pki.roster.write_text(json.dumps(signed))
    with pytest.raises(TrustError, match="not signed by the root"):
        load_roster(pki)


def test_device_keys_persist_and_csr_has_pop(device: DeviceKeys) -> None:
    again, created = DeviceKeys.load_or_create(device.key_dir, device.device_id)
    assert not created and again.fingerprint == device.fingerprint
    assert x509.load_pem_x509_csr(device.csr_pem).is_signature_valid


# --- approvals ---------------------------------------------------------------------------------


def test_two_of_three_issues(pki: PkiPaths, device: DeviceKeys) -> None:
    for pair in [("A", "B"), ("B", "C"), ("A", "C"), ("A", "B", "C")]:
        cert = issue(pki, device, *pair)
        ident = verify_device_cert(cert, *root(pki), expected_id="garage-lock")
        assert ident.fingerprint == device.fingerprint


def test_single_admin_cannot_issue(pki: PkiPaths, device: DeviceKeys) -> None:
    with pytest.raises(TrustError, match="needs 2 admin approvals, has 1"):
        issue(pki, device, "A")


def test_same_admin_twice_counts_once(pki: PkiPaths, device: DeviceKeys) -> None:
    action = approvals.new_action("add-device", "garage-lock", device.csr_pem)
    sig = approvals.sign_approval(load_admin_key(pki, "A"), action)
    assert approvals.valid_approvers(action, {"A": sig}, load_roster(pki)) == ["A"]
    # Reusing A's signature under B's name does not verify against B's key.
    with pytest.raises(TrustError):
        issue_device_cert(pki, action, device.csr_pem, {"A": sig, "B": sig})


def test_non_admin_signature_ignored(pki: PkiPaths, device: DeviceKeys) -> None:
    action = approvals.new_action("add-device", "garage-lock", device.csr_pem)
    rogue = Ed25519PrivateKey.generate()
    sigs = {"A": approvals.sign_approval(load_admin_key(pki, "A"), action)}
    sigs["D"] = approvals.sign_approval(rogue, action)
    with pytest.raises(TrustError, match="has 1"):
        issue_device_cert(pki, action, device.csr_pem, sigs)


def test_signature_for_other_action_rejected(pki: PkiPaths, device: DeviceKeys) -> None:
    action = approvals.new_action("add-device", "garage-lock", device.csr_pem)
    other = approvals.new_action("add-device", "garage-lock", device.csr_pem)  # new nonce
    sigs = approve(pki, other, "A", "B")
    with pytest.raises(TrustError, match="has 0"):
        issue_device_cert(pki, action, device.csr_pem, sigs)


def test_approved_action_cannot_be_reused_for_other_csr(pki: PkiPaths, device: DeviceKeys) -> None:
    action = approvals.new_action("add-device", "garage-lock", device.csr_pem)
    sigs = approve(pki, action, "A", "B")
    attacker_csr = build_csr(
        "garage-lock", Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
    )
    with pytest.raises(TrustError, match="CSR does not match"):
        issue_device_cert(pki, action, attacker_csr, sigs)


def test_csr_for_wrong_device_rejected(pki: PkiPaths) -> None:
    csr = build_csr("front-door", Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    action = approvals.new_action("add-device", "garage-lock", csr)
    with pytest.raises(TrustError, match="subject does not match"):
        issue_device_cert(pki, action, csr, approve(pki, action, "A", "B"))


def test_csr_with_bad_pop_rejected(pki: PkiPaths, device: DeviceKeys) -> None:
    der = bytearray(x509.load_pem_x509_csr(device.csr_pem).public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01  # corrupt the signature
    pem = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    action = approvals.new_action("add-device", "garage-lock", pem)
    with pytest.raises(TrustError, match="proof-of-possession"):
        issue_device_cert(pki, action, pem, approve(pki, action, "A", "B"))


@pytest.mark.parametrize("bad", ["Garage", "x", "translog", "a/b", "../root", "dashboard"])
def test_bad_device_ids_rejected(bad: str) -> None:
    with pytest.raises(TrustError):
        approvals.new_action("add-device", bad, b"csr")


def test_remove_action_cannot_issue(pki: PkiPaths, device: DeviceKeys) -> None:
    action = approvals.new_action("remove-device", "garage-lock")
    with pytest.raises(TrustError, match="not add-device"):
        issue_device_cert(pki, action, device.csr_pem, approve(pki, action, "A", "B"))


# --- certificate verification ------------------------------------------------------------------


def test_cert_from_another_root_rejected(pki: PkiPaths, device: DeviceKeys, tmp_path: Path):
    evil = PkiPaths(tmp_path / "evil-off", tmp_path / "evil-pub", tmp_path / "evil-log")
    init_pki(evil)
    forged = issue(evil, device)
    with pytest.raises(TrustError):
        verify_device_cert(forged, *root(pki))


def test_cert_signed_by_imposter_with_same_name_rejected(pki: PkiPaths, device: DeviceKeys):
    """An attacker copies the root's *name* but signs with their own key."""
    real_root, _ = root(pki)
    imposter = Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name.from_rfc4514_string("CN=garage-lock"))
        .issuer_name(real_root.subject)
        .public_key(device.sign_key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime.now(dt.UTC))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
        .sign(imposter, None)
    )
    with pytest.raises(TrustError, match="signature does not verify"):
        verify_device_cert(cert, *root(pki))


def test_wrong_expected_id_rejected(pki: PkiPaths, device: DeviceKeys) -> None:
    with pytest.raises(TrustError, match="expected 'front-door'"):
        verify_device_cert(issue(pki, device), *root(pki), expected_id="front-door")


def test_expired_rejected(pki: PkiPaths, device: DeviceKeys) -> None:
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=400)
    with pytest.raises(TrustError, match="expired"):
        verify_device_cert(issue(pki, device), *root(pki), now=later)


def test_log_cert_is_not_a_device_cert(pki: PkiPaths) -> None:
    log_cert = x509.load_pem_x509_certificate(pki.translog_crt.read_bytes())
    with pytest.raises(TrustError):
        verify_device_cert(log_cert, *root(pki))


def test_device_cert_is_not_a_log_cert(pki: PkiPaths, device: DeviceKeys) -> None:
    with pytest.raises(TrustError):
        verify_service_cert(issue(pki, device), *root(pki), "garage-lock")


# --- tree heads --------------------------------------------------------------------------------


def _sth(key: Ed25519PrivateKey, size: int = 5) -> TreeHead:
    root_hash = bytes(32)
    return TreeHead(size, 1000, root_hash, key.sign(sth_message(size, 1000, root_hash)))


def test_sth_signature(pki: PkiPaths) -> None:
    log_cert = x509.load_pem_x509_certificate(pki.translog_crt.read_bytes())
    log_pub = verify_service_cert(log_cert, *root(pki), "translog")
    log_key = read_private(pki.translog_key)
    sth = _sth(log_key)
    verify_sth(sth, log_pub)
    verify_sth(TreeHead.from_json(sth.as_json()), log_pub)
    with pytest.raises(TrustError):
        verify_sth(TreeHead(6, sth.timestamp_ms, sth.root_hash, sth.signature), log_pub)
    with pytest.raises(TrustError):
        verify_sth(_sth(Ed25519PrivateKey.generate()), log_pub)


# --- KDC certificate + revocations (phase 3/4) -------------------------------------------------


def test_kdc_cert_issued_and_is_not_a_log_cert(pki: PkiPaths) -> None:
    kdc_cert = x509.load_pem_x509_certificate(pki.kdc_crt.read_bytes())
    verify_service_cert(kdc_cert, *root(pki), "kdc")
    with pytest.raises(TrustError):
        verify_service_cert(kdc_cert, *root(pki), "translog")


def test_kdc_cert_added_to_existing_pki(pki: PkiPaths) -> None:
    pki.kdc_crt.unlink()
    assert init_pki(pki) == ["KDC signing key certified by root"]
    assert pki.kdc_crt.is_file()


def test_revocation_needs_two_admins_and_root_signature(pki: PkiPaths, device: DeviceKeys):
    from rootca.root import issue_revocation
    from securelib.pki import verify_revocation

    cert = issue(pki, device)
    serial = format(cert.serial_number, "x")
    action = approvals.new_action("remove-device", "garage-lock")
    with pytest.raises(TrustError, match="has 1"):
        issue_revocation(pki, action, approve(pki, action, "C"), serial)
    signed, approvers = issue_revocation(pki, action, approve(pki, action, "A", "C"), serial)
    assert approvers == ["A", "C"]
    _, root_pub = root(pki)
    assert verify_revocation(signed, root_pub) == ("garage-lock", cert.serial_number)

    forged = {**signed, "revocation": {**signed["revocation"], "device_id": "front-door"}}
    with pytest.raises(TrustError, match="not signed by the root"):
        verify_revocation(forged, root_pub)


def test_add_action_cannot_revoke(pki: PkiPaths, device: DeviceKeys) -> None:
    from rootca.root import issue_revocation

    action = approvals.new_action("add-device", "garage-lock", device.csr_pem)
    with pytest.raises(TrustError, match="not remove-device"):
        issue_revocation(pki, action, approve(pki, action, "A", "B"), "01")


# --- one live certificate per device key ------------------------------------------------------


class _FakeDirectory:
    def __init__(self, entry: dict | None) -> None:
        self.entry = entry

    def get_cert(self, device_id: str) -> dict | None:
        return self.entry

    def list_revocations(self) -> list[dict]:
        return []


@pytest.mark.parametrize("revoked", [False, True])
def test_second_cert_for_same_key_refused_until_revoked(
    pki: PkiPaths, device: DeviceKeys, monkeypatch: pytest.MonkeyPatch, revoked: bool
) -> None:
    """Re-pairing a commissioned device would leave a valid certificate behind that
    survives revocation of the newer one: pairing must refuse until it is revoked."""
    from cli import pki_actions

    cert = issue(pki, device)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    entry = {"cert_pem": pem, "fingerprint": device.fingerprint, "leaf_index": 3}
    monkeypatch.setattr(pki_actions, "directory", lambda cfg, identity: _FakeDirectory(entry))

    class Anchors:
        def revoked(self, _signed: list) -> dict[str, set[int]]:
            return {"garage-lock": {cert.serial_number}} if revoked else {}

    monkeypatch.setattr(pki_actions.TrustAnchors, "from_config", lambda cfg: Anchors())
    if revoked:
        pki_actions._refuse_second_cert(None, "garage-lock", device.fingerprint, "cli")
    else:
        with pytest.raises(TrustError, match="already commissioned"):
            pki_actions._refuse_second_cert(None, "garage-lock", device.fingerprint, "cli")
    # new keys (device reset) are not blocked by this check
    pki_actions._refuse_second_cert(None, "garage-lock", "00:11", "cli")
