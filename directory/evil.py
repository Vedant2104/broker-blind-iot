"""What a compromised directory can do (attacks 9 and 10).

It holds no private keys, so the best it can do is lie: serve a certificate and
an MLS key package for a device that are really the attacker's. It cannot get
the root to sign, so its forged certificate copies the root's *name* and is
signed with the attacker's own key.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from securelib.pki import DEVICE_EKU, raw_public, x25519_extension


def forge_device_cert(device_id: str, root: x509.Certificate) -> tuple[str, Ed25519PrivateKey]:
    """A certificate that *claims* the bbiot root as issuer, signed by the attacker."""
    attacker = Ed25519PrivateKey.generate()
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .issuer_name(root.subject)  # looks right...
        .public_key(attacker.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
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
        .add_extension(x509.ExtendedKeyUsage([DEVICE_EKU]), critical=False)
        .add_extension(x25519_extension(X25519PrivateKey.generate().public_key()), critical=False)
        .sign(attacker, None)  # ...but signed by the attacker, not the root
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), attacker


def forge_key_package(device_id: str, attacker: Ed25519PrivateKey) -> str | None:
    """A valid MLS key package for `device_id`, signed with the attacker's key."""
    try:
        from securelib.mls import MlsError, MlsSidecar
    except ImportError:
        return None
    try:
        side = MlsSidecar()
    except MlsError:
        return None
    try:
        side.call(
            "init",
            identity=device_id,
            sig_priv=attacker.private_bytes_raw().hex(),
            sig_pub=raw_public(attacker.public_key()).hex(),
        )
        return side.call("key_package")["key_package"]
    finally:
        side.close()
