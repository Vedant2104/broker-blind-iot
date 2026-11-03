"""The offline root: creates the trust anchors and signs certificates.

Its private key lives in the offline directory (default ./offline), which is
never mounted into the running system. Only the one-shot setup step and the
admin's own machine (the host CLI) use it.

Layout
  offline/root.key                  root signing key (Ed25519)
  offline/admins/{A,B,C}.key        each admin's signing key (simulated: one dir)
  secrets/pki/public/root.crt       root certificate (distributed to everyone)
  secrets/pki/public/admins.json    admin roster signed by the root
  secrets/pki/public/translog.crt   transparency log key, certified by the root
  secrets/translog/log.key          log signing key (mounted only into translog)
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

from rootca import approvals
from securelib.identity import read_private, write_private
from securelib.pki import (
    DEVICE_EKU,
    LOG_EKU,
    SERVICE_EKUS,
    X25519_EXT_OID,
    TrustError,
    load_root,
    raw_public,
    read_x25519_extension,
    sign_revocation,
    x25519_extension,
)

ROOT_DAYS = 3650
CERT_DAYS = 365


@dataclass(frozen=True)
class PkiPaths:
    offline: Path
    public: Path
    translog_key: Path

    @property
    def root_key(self) -> Path:
        return self.offline / "root.key"

    def admin_key(self, admin: str) -> Path:
        return self.offline / "admins" / f"{admin}.key"

    @property
    def root_crt(self) -> Path:
        return self.public / "root.crt"

    @property
    def roster(self) -> Path:
        return self.public / "admins.json"

    @property
    def translog_crt(self) -> Path:
        return self.public / "translog.crt"

    @property
    def kdc_crt(self) -> Path:
        return self.public / "kdc.crt"

    @property
    def kdc_key(self) -> Path:
        """KDC signing key (mounted only into the KDC): <secrets>/kdc/kdc.key."""
        return self.translog_key.parent.parent / "kdc" / "kdc.key"


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Broker-Blind IoT"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _leaf_builder(
    subject_cn: str, root_cert: x509.Certificate, root_key: Ed25519PrivateKey, pub, days: int
) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(root_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )


def make_root(root_key: Ed25519PrivateKey) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    name = _name("bbiot offline root")
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=ROOT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, None)
    )


def pki_exists(paths: PkiPaths) -> bool:
    return all(
        p.is_file() for p in (paths.root_key, paths.root_crt, paths.roster, paths.translog_crt)
    )


def _issue_service_cert(paths: PkiPaths, name: str, key_path: Path, crt_path: Path) -> None:
    root_key = read_private(paths.root_key)
    root_cert, _ = load_root(paths.root_crt.read_bytes())
    key = Ed25519PrivateKey.generate()
    write_private(key_path, key)
    cert = (
        _leaf_builder(name, root_cert, root_key, key.public_key(), ROOT_DAYS)
        .add_extension(x509.ExtendedKeyUsage([SERVICE_EKUS[name]]), critical=False)
        .sign(root_key, None)
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _ensure_services(paths: PkiPaths) -> list[str]:
    notes = []
    if not paths.kdc_crt.is_file() or not paths.kdc_key.is_file():
        _issue_service_cert(paths, "kdc", paths.kdc_key, paths.kdc_crt)
        notes.append("KDC signing key certified by root")
    return notes


def init_pki(paths: PkiPaths, *, force: bool = False) -> list[str]:
    """Create root, admin keys + signed roster, and the log key + its certificate."""
    if pki_exists(paths) and not force:
        return _ensure_services(paths)  # add service certs introduced by later phases
    notes = []
    root_key = Ed25519PrivateKey.generate()
    write_private(paths.root_key, root_key)
    root_cert = make_root(root_key)
    paths.public.mkdir(parents=True, exist_ok=True)
    paths.root_crt.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    notes.append(f"root key -> {paths.root_key.as_posix()} (offline)")

    pubs = {}
    for admin in approvals.ADMINS:
        key = Ed25519PrivateKey.generate()
        write_private(paths.admin_key(admin), key)
        pubs[admin] = raw_public(key.public_key())
    signed = approvals.sign_roster(root_key, approvals.make_roster(pubs))
    paths.roster.write_text(json.dumps(signed, indent=2), encoding="utf-8")
    notes.append(f"admins A, B, C (threshold {approvals.THRESHOLD}) -> roster signed by root")

    log_key = Ed25519PrivateKey.generate()
    write_private(paths.translog_key, log_key)
    log_cert = (
        _leaf_builder("translog", root_cert, root_key, log_key.public_key(), ROOT_DAYS)
        .add_extension(x509.ExtendedKeyUsage([LOG_EKU]), critical=False)
        .sign(root_key, None)
    )
    paths.translog_crt.write_bytes(log_cert.public_bytes(serialization.Encoding.PEM))
    notes.append("transparency log key certified by root")
    if force:
        paths.kdc_crt.unlink(missing_ok=True)
    return notes + _ensure_services(paths)


def issue_revocation(
    paths: PkiPaths, action: dict, approval_sigs: dict[str, str], serial_hex: str
) -> tuple[dict, list[str]]:
    """Root-signed revocation — only for a remove-device action approved by 2 of 3."""
    roster = load_roster(paths)
    approvers = approvals.require_threshold(action, approval_sigs, roster)
    if action.get("type") != "remove-device":
        raise TrustError("action is not remove-device")
    approvals.check_device_id(action["device_id"])
    statement = {
        "device_id": action["device_id"],
        "serial": serial_hex,
        "action_id": approvals.action_id(action),
        "revoked_ms": int(dt.datetime.now(dt.UTC).timestamp() * 1000),
    }
    return sign_revocation(read_private(paths.root_key), statement), approvers


def load_roster(paths: PkiPaths) -> dict:
    _, root_pub = load_root(paths.root_crt.read_bytes())
    return approvals.verify_roster(json.loads(paths.roster.read_text("utf-8")), root_pub)


def load_admin_key(paths: PkiPaths, admin: str) -> Ed25519PrivateKey:
    path = paths.admin_key(admin)
    if not path.is_file():
        raise TrustError(f"admin {admin}'s key is not on this machine ({path.as_posix()})")
    return read_private(path)


def issue_device_cert(
    paths: PkiPaths, action: dict, csr_pem: bytes, approval_sigs: dict[str, str]
) -> tuple[bytes, list[str]]:
    """Sign a device certificate — only for an add-device action approved by
    2 of 3 admins, and only for the exact CSR that action names."""
    roster = load_roster(paths)
    approvers = approvals.require_threshold(action, approval_sigs, roster)

    if action.get("type") != "add-device":
        raise TrustError("action is not add-device")
    approvals.check_device_id(action["device_id"])
    if hashlib.sha256(csr_pem).hexdigest() != action.get("csr_sha256"):
        raise TrustError("CSR does not match the approved action")

    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise TrustError("CSR proof-of-possession signature invalid")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != action["device_id"]:
        raise TrustError("CSR subject does not match the device id")
    if not isinstance(csr.public_key(), Ed25519PublicKey):
        raise TrustError("CSR key is not Ed25519")
    kx = read_x25519_extension(csr.extensions)
    if [e.oid for e in csr.extensions] != [X25519_EXT_OID]:
        raise TrustError("CSR requests unexpected extensions")

    root_key = read_private(paths.root_key)
    root_cert, _ = load_root(paths.root_crt.read_bytes())
    cert = (
        _leaf_builder(action["device_id"], root_cert, root_key, csr.public_key(), CERT_DAYS)
        .add_extension(x509.ExtendedKeyUsage([DEVICE_EKU]), critical=False)
        .add_extension(x25519_extension(kx), critical=False)
        .sign(root_key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM), approvers
