"""Transport TLS material: chain validity, and a real mTLS handshake where
clients without a valid certificate are rejected."""

from __future__ import annotations

import os
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from securelib.config import Config
from securelib.tls import client_paths, fingerprint, init_tls


def _load(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


@pytest.fixture
def tls_dir(cfg: Config) -> Path:
    init_tls(cfg.tls_dir, cfg.identities)
    return cfg.tls_dir


def test_chain_is_signed_by_ca(tls_dir: Path, cfg: Config) -> None:
    ca = _load(tls_dir / "ca.crt")
    _load(tls_dir / "broker" / "broker.crt").verify_directly_issued_by(ca)
    for name in cfg.identities:
        _load(client_paths(tls_dir, name).cert).verify_directly_issued_by(ca)


def test_broker_cert_names_and_usage(tls_dir: Path) -> None:
    cert = _load(tls_dir / "broker" / "broker.crt")
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {"broker", "localhost"} <= set(sans.get_values_for_type(x509.DNSName))
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_client_cert_identity_and_usage(tls_dir: Path) -> None:
    cert = _load(client_paths(tls_dir, "front-door").cert)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "front-door"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert ExtendedKeyUsageOID.SERVER_AUTH not in eku


def test_rerun_keeps_existing_material(tls_dir: Path, cfg: Config) -> None:
    before = fingerprint(tls_dir / "ca.crt")
    assert init_tls(cfg.tls_dir, cfg.identities) == []
    assert fingerprint(tls_dir / "ca.crt") == before


def test_new_client_added_without_new_ca(tls_dir: Path, cfg: Config) -> None:
    before = fingerprint(tls_dir / "ca.crt")
    written = init_tls(cfg.tls_dir, [*cfg.identities, "garage-lock"])
    assert written == [client_paths(tls_dir, "garage-lock").cert]
    assert fingerprint(tls_dir / "ca.crt") == before


def test_force_rotates_ca(tls_dir: Path, cfg: Config) -> None:
    before = fingerprint(tls_dir / "ca.crt")
    init_tls(cfg.tls_dir, cfg.identities, force=True)
    assert fingerprint(tls_dir / "ca.crt") != before


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_private_keys_are_owner_only(tls_dir: Path) -> None:
    for key in [tls_dir / "ca.key", *tls_dir.glob("**/*.key")]:
        assert os.stat(key).st_mode & 0o077 == 0, key


# --- real mTLS handshake against a local TLS server ---------------------------


def _mtls_server(tls_dir: Path) -> tuple[int, threading.Thread, list[str]]:
    """A one-connection TLS server that requires a client cert from our CA."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(tls_dir / "ca.crt"))
    ctx.load_cert_chain(tls_dir / "broker" / "broker.crt", tls_dir / "broker" / "broker.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    sock.settimeout(5)
    outcome: list[str] = []

    def serve() -> None:
        conn, _ = sock.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                peer = tls.getpeercert()
                cn = dict(x[0] for x in peer["subject"])["commonName"]
                outcome.append(f"accepted:{cn}")
                tls.sendall(b"ok")
        except (ssl.SSLError, OSError) as exc:
            outcome.append(f"rejected:{type(exc).__name__}")
        finally:
            sock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return sock.getsockname()[1], t, outcome


def _connect(port: int, ca: Path, cert: Path | None, key: Path | None) -> bytes:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    if cert and key:
        ctx.load_cert_chain(cert, key)
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        ctx.wrap_socket(raw, server_hostname="localhost") as tls,
    ):
        return tls.recv(2)


def test_mtls_accepts_valid_client(tls_dir: Path) -> None:
    port, t, outcome = _mtls_server(tls_dir)
    p = client_paths(tls_dir, "phone")
    assert _connect(port, p.ca, p.cert, p.key) == b"ok"
    t.join(5)
    assert outcome == ["accepted:phone"]


def test_mtls_rejects_client_without_cert(tls_dir: Path) -> None:
    port, t, outcome = _mtls_server(tls_dir)
    with pytest.raises((ssl.SSLError, OSError)):
        data = _connect(port, tls_dir / "ca.crt", None, None)
        if not data:  # TLS 1.3: rejection may surface as a closed stream
            raise ConnectionResetError("closed by server")
    t.join(5)
    assert outcome and outcome[0].startswith("rejected")


def test_mtls_rejects_cert_from_other_ca(tls_dir: Path, tmp_path: Path) -> None:
    """A counterfeit client with a self-made CA must be refused."""
    rogue = tmp_path / "rogue"
    init_tls(rogue, ["front-door"])
    port, t, outcome = _mtls_server(tls_dir)
    p = client_paths(rogue, "front-door")
    with pytest.raises((ssl.SSLError, OSError)):
        data = _connect(port, tls_dir / "ca.crt", p.cert, p.key)
        if not data:
            raise ConnectionResetError("closed by server")
    t.join(5)
    assert outcome and outcome[0].startswith("rejected")


def test_empty_placeholder_dirs_do_not_count_as_material(tmp_path: Path) -> None:
    """Docker bind mounts can leave empty dirs where cert files should be."""
    from securelib.tls import tls_material_exists

    (tmp_path / "ca.crt").mkdir()
    (tmp_path / "broker" / "broker.crt").mkdir(parents=True)
    assert not tls_material_exists(tmp_path)
