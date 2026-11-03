"""Transport TLS material for mTLS between clients and the MQTT broker.

This is the *transport* layer only (the "security OFF" baseline). The broker
still sees plaintext inside TLS. End-to-end protection comes in later phases,
and device identity certificates come from the offline root (rootca/).

Layout written under <secrets>/tls/:
  ca.crt, ca.key                 transport CA
  broker/ca.crt, broker.crt, broker.key
                                 everything the broker mounts (one folder)
  clients/<name>.crt, <name>.key one client cert per device/service
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BROKER_DNS_NAMES = ("broker", "evil-broker", "localhost")
VALIDITY_DAYS = 365


@dataclass(frozen=True)
class ClientPaths:
    ca: Path
    cert: Path
    key: Path


def client_paths(tls_dir: Path, name: str) -> ClientPaths:
    return ClientPaths(
        ca=tls_dir / "ca.crt",
        cert=tls_dir / "clients" / f"{name}.crt",
        key=tls_dir / "clients" / f"{name}.key",
    )


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Broker-Blind IoT (dev)"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _builder(subject: x509.Name, issuer: x509.Name, public_key) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
    )


def make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _new_key()
    name = _name("bbiot transport CA")
    cert = (
        _builder(name, name, key.public_key())
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    *,
    server: bool,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _new_key()
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        _builder(_name(cn), ca_cert.subject, key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if server:
        sans: list[x509.GeneralName] = [x509.DNSName(n) for n in BROKER_DNS_NAMES]
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey, owner_uid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Create with owner-only permissions from the start.
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if owner_uid is not None and hasattr(os, "chown"):
        os.chown(path, owner_uid, owner_uid)


def tls_material_exists(tls_dir: Path) -> bool:
    return all((tls_dir / p).is_file() for p in ("ca.crt", "broker/ca.crt", "broker/broker.crt"))


def init_tls(
    tls_dir: Path,
    clients: list[str],
    *,
    force: bool = False,
    broker_key_uid: int | None = None,
) -> list[Path]:
    """Create the transport CA, broker cert and client certs. Returns written cert paths.

    Existing material is kept unless ``force``; missing client certs are added.
    ``broker_key_uid`` chowns the broker key so the (non-root) broker can read it.
    """
    written: list[Path] = []
    ca_key_path, ca_crt_path = tls_dir / "ca.key", tls_dir / "ca.crt"

    if force or not ca_crt_path.exists():
        ca_key, ca_cert = make_ca()
        _write_key(ca_key_path, ca_key)
        _write_cert(ca_crt_path, ca_cert)
        written.append(ca_crt_path)
        force = True  # a new CA invalidates everything signed by the old one
    else:
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    broker_crt = tls_dir / "broker" / "broker.crt"
    if force or not broker_crt.exists():
        key, cert = issue_cert(ca_key, ca_cert, "broker", server=True)
        _write_key(tls_dir / "broker" / "broker.key", key, owner_uid=broker_key_uid)
        _write_cert(broker_crt, cert)
        _write_cert(tls_dir / "broker" / "ca.crt", ca_cert)
        written.append(broker_crt)

    for name in clients:
        paths = client_paths(tls_dir, name)
        if force or not paths.cert.exists():
            key, cert = issue_cert(ca_key, ca_cert, name, server=False)
            _write_key(paths.key, key)
            _write_cert(paths.cert, cert)
            written.append(paths.cert)

    return written


def fingerprint(cert_path: Path) -> str:
    """SHA-256 fingerprint of a certificate, colon-separated (safe to log)."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex(":")
