"""A device's own identity: key generation, storage and the signing request.

Private keys are created on the device, written with owner-only permissions to
the device's own key directory, and never sent anywhere. Only the CSR (public
keys + a proof-of-possession signature) leaves the device.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from securelib.pki import fingerprint, pairing_code, raw_public, x25519_extension


def write_private(path: Path, key: Ed25519PrivateKey | X25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def read_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def build_csr(device_id: str, sign_key: Ed25519PrivateKey, kx_key: X25519PrivateKey) -> bytes:
    """PKCS#10 request: CN=device id, X25519 key as a requested extension, signed
    with the Ed25519 key (proves possession of it and binds the X25519 key)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .add_extension(x25519_extension(kx_key.public_key()), critical=False)
        .sign(sign_key, None)
    )
    return csr.public_bytes(serialization.Encoding.PEM)


@dataclass
class DeviceKeys:
    device_id: str
    sign_key: Ed25519PrivateKey
    kx_key: X25519PrivateKey
    key_dir: Path

    @property
    def ed25519_raw(self) -> bytes:
        return raw_public(self.sign_key.public_key())

    @property
    def x25519_raw(self) -> bytes:
        return raw_public(self.kx_key.public_key())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.ed25519_raw + self.x25519_raw)

    @property
    def pairing_code(self) -> str:
        return pairing_code(self.ed25519_raw, self.x25519_raw)

    @property
    def csr_pem(self) -> bytes:
        return (self.key_dir / "request.csr").read_bytes()

    @property
    def cert_path(self) -> Path:
        return self.key_dir / "device.crt"

    @classmethod
    def load_or_create(cls, key_dir: Path, device_id: str) -> tuple[DeviceKeys, bool]:
        """Returns (keys, created)."""
        sign_path, kx_path = key_dir / "ed25519.key", key_dir / "x25519.key"
        created = not (sign_path.exists() and kx_path.exists())
        if created:
            sign_key, kx_key = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
            write_private(sign_path, sign_key)
            write_private(kx_path, kx_key)
            (key_dir / "device.crt").unlink(missing_ok=True)
        else:
            sign_key, kx_key = read_private(sign_path), read_private(kx_path)
        csr_path = key_dir / "request.csr"
        if created or not csr_path.exists():
            csr_path.write_bytes(build_csr(device_id, sign_key, kx_key))
        return cls(device_id, sign_key, kx_key, key_dir), created
