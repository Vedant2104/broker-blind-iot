"""Device identity certificates and their verification.

Device certificate = standard X.509 v3, issued by the offline Ed25519 root:
  subject CN        device id
  public key        the device's Ed25519 signing key
  extension (ours)  the device's X25519 key-agreement public key (non-critical)
  BasicConstraints  CA=false (critical); KeyUsage digitalSignature (critical)

Every check here has a negative-case unit test (tests/test_pki.py).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.x509.oid import NameOID

# Private OID for the X25519 extension, under the UUID arc 2.25 (ITU-T X.667),
# which needs no registration.
X25519_EXT_OID = x509.ObjectIdentifier(
    "2.25." + str(uuid.UUID("6f1c2a8e-93b4-4d57-a0e2-5c7d19b3f846").int)
)
# Extended key usages that separate device certs from service (log) certs.
_ARC = "2.25." + str(uuid.UUID("0b7e4f7a-2a51-4f0e-9a43-1d2b8f7c6e15").int)
DEVICE_EKU = x509.ObjectIdentifier(_ARC + ".1")
LOG_EKU = x509.ObjectIdentifier(_ARC + ".2")
KDC_EKU = x509.ObjectIdentifier(_ARC + ".3")
SERVICE_EKUS = {"translog": LOG_EKU, "kdc": KDC_EKU}
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


class TrustError(Exception):
    """A certificate, signature or proof failed verification. The message is the reason."""


# --- helpers ------------------------------------------------------------------------------


def raw_public(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(*RAW)


def fingerprint(data: bytes) -> str:
    """SHA-256 fingerprint, colon hex (first 16 bytes — enough to display and compare)."""
    return hashlib.sha256(data).digest()[:16].hex(":")


def pairing_code(ed25519_raw: bytes, x25519_raw: bytes) -> str:
    """Short code shown on the device (QR) and by the pairing tool for comparison."""
    digest = hashlib.sha256(b"bbiot-pairing-v1" + ed25519_raw + x25519_raw).hexdigest()
    return "-".join(digest[i : i + 4].upper() for i in range(0, 20, 4))


def x25519_extension(key: X25519PublicKey) -> x509.UnrecognizedExtension:
    # extnValue holds a DER OCTET STRING wrapping the 32-byte key.
    raw = raw_public(key)
    return x509.UnrecognizedExtension(X25519_EXT_OID, b"\x04\x20" + raw)


def read_x25519_extension(exts: x509.Extensions) -> X25519PublicKey:
    try:
        ext = exts.get_extension_for_oid(X25519_EXT_OID).value
    except x509.ExtensionNotFound as exc:
        raise TrustError("missing X25519 key extension") from exc
    value = ext.value  # type: ignore[attr-defined]
    if len(value) != 34 or value[:2] != b"\x04\x20":
        raise TrustError("malformed X25519 key extension")
    return X25519PublicKey.from_public_bytes(value[2:])


def common_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attrs) != 1:
        raise TrustError("certificate must have exactly one CN")
    return str(attrs[0].value)


def check_eku(cert: x509.Certificate, required: x509.ObjectIdentifier) -> None:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TrustError("missing extended key usage") from exc
    if required not in eku:
        raise TrustError("certificate is not issued for this purpose")


def verify_signed_by(cert: x509.Certificate, issuer_key: Ed25519PublicKey) -> None:
    try:
        issuer_key.verify(cert.signature, cert.tbs_certificate_bytes)
    except InvalidSignature as exc:
        raise TrustError("certificate signature does not verify against the root") from exc


# --- root ---------------------------------------------------------------------------------


def load_root(pem: bytes) -> tuple[x509.Certificate, Ed25519PublicKey]:
    """Load and self-check the root certificate."""
    cert = x509.load_pem_x509_certificate(pem)
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise TrustError("root key is not Ed25519")
    verify_signed_by(cert, key)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not bc.ca:
        raise TrustError("root certificate is not a CA")
    return cert, key


# --- device certificates ----------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    ed25519: Ed25519PublicKey
    x25519: X25519PublicKey
    serial: int
    der: bytes

    @property
    def ed25519_raw(self) -> bytes:
        return raw_public(self.ed25519)

    @property
    def x25519_raw(self) -> bytes:
        return raw_public(self.x25519)

    @property
    def fingerprint(self) -> str:
        """Fingerprint over both public keys — what gets pinned and displayed."""
        return fingerprint(self.ed25519_raw + self.x25519_raw)


def verify_device_cert(
    cert: x509.Certificate,
    root: x509.Certificate,
    root_key: Ed25519PublicKey,
    *,
    expected_id: str | None = None,
    now: dt.datetime | None = None,
) -> DeviceIdentity:
    """Full check of a device certificate against the offline root."""
    if cert.issuer != root.subject:
        raise TrustError("issuer is not the bbiot root")
    verify_signed_by(cert, root_key)

    now = now or dt.datetime.now(dt.UTC)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise TrustError("certificate is expired or not yet valid")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TrustError("missing BasicConstraints or KeyUsage") from exc
    if bc.ca:
        raise TrustError("device certificate must not be a CA")
    if not ku.digital_signature or ku.key_cert_sign:
        raise TrustError("wrong key usage for a device certificate")
    check_eku(cert, DEVICE_EKU)

    device_id = common_name(cert.subject)
    if expected_id is not None and device_id != expected_id:
        raise TrustError(f"certificate is for '{device_id}', expected '{expected_id}'")

    ed = cert.public_key()
    if not isinstance(ed, Ed25519PublicKey):
        raise TrustError("device key is not Ed25519")
    xk = read_x25519_extension(cert.extensions)
    return DeviceIdentity(
        device_id=device_id,
        ed25519=ed,
        x25519=xk,
        serial=cert.serial_number,
        der=cert.public_bytes(serialization.Encoding.DER),
    )


def verify_service_cert(
    cert: x509.Certificate, root: x509.Certificate, root_key: Ed25519PublicKey, name: str
) -> Ed25519PublicKey:
    """Check a root-issued certificate for a service key (e.g. the transparency log)."""
    if cert.issuer != root.subject:
        raise TrustError("issuer is not the bbiot root")
    verify_signed_by(cert, root_key)
    now = dt.datetime.now(dt.UTC)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise TrustError("certificate is expired or not yet valid")
    if common_name(cert.subject) != name:
        raise TrustError(f"certificate is not for '{name}'")
    if name not in SERVICE_EKUS:
        raise TrustError(f"'{name}' is not a known service")
    check_eku(cert, SERVICE_EKUS[name])
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise TrustError("service key is not Ed25519")
    return key


# --- signed tree heads ---------------------------------------------------------------------------


STH_CONTEXT = b"bbiot-sth-v1"


@dataclass(frozen=True)
class TreeHead:
    tree_size: int
    timestamp_ms: int
    root_hash: bytes
    signature: bytes

    def signed_bytes(self) -> bytes:
        return sth_message(self.tree_size, self.timestamp_ms, self.root_hash)

    def as_json(self) -> dict:
        return {
            "tree_size": self.tree_size,
            "timestamp_ms": self.timestamp_ms,
            "root_hash": self.root_hash.hex(),
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_json(cls, d: dict) -> TreeHead:
        try:
            return cls(
                tree_size=int(d["tree_size"]),
                timestamp_ms=int(d["timestamp_ms"]),
                root_hash=bytes.fromhex(d["root_hash"]),
                signature=bytes.fromhex(d["signature"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise TrustError("malformed signed tree head") from exc


def sth_message(tree_size: int, timestamp_ms: int, root: bytes) -> bytes:
    return STH_CONTEXT + tree_size.to_bytes(8, "big") + timestamp_ms.to_bytes(8, "big") + root


def verify_sth(sth: TreeHead, log_key: Ed25519PublicKey) -> None:
    if len(sth.root_hash) != 32 or sth.tree_size < 0:
        raise TrustError("malformed signed tree head")
    try:
        log_key.verify(sth.signature, sth.signed_bytes())
    except InvalidSignature as exc:
        raise TrustError("tree head signature invalid (not signed by the log)") from exc


# --- revocations ---------------------------------------------------------------------------------

REVOCATION_CONTEXT = b"bbiot-revocation-v1"


def _canonical(obj: object) -> bytes:
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign_revocation(root_key, statement: dict) -> dict:
    return {
        "revocation": statement,
        "signature": root_key.sign(REVOCATION_CONTEXT + _canonical(statement)).hex(),
    }


def verify_revocation(signed: dict, root_key: Ed25519PublicKey) -> tuple[str, int]:
    """Returns (device_id, revoked certificate serial)."""
    try:
        st = signed["revocation"]
        root_key.verify(bytes.fromhex(signed["signature"]), REVOCATION_CONTEXT + _canonical(st))
        return str(st["device_id"]), int(st["serial"], 16)
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise TrustError("revocation is not signed by the root") from exc
