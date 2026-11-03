"""Centralized mode: authenticated key exchange between a device and the KDC.

Signed ephemeral Diffie-Hellman (ISO/IEC 9798-3 style, as in TLS 1.3's
CertificateVerify): each side signs a transcript containing BOTH identities,
BOTH ephemeral X25519 shares, both nonces and the auth mode. The resulting
pairwise key-encryption key (KEK) wraps every group key the KDC sends.

   device → KDC   hello     {device, eph_D, nonce_D, auth}
   KDC → device   challenge {eph_K, nonce_K, sig_K(transcript)}
   device → KDC   finish    {sig_D(transcript)}
   KDC → device   key       {epoch, nonce, AEAD_KEK(group key)}      (also on every rekey)

These messages travel over MQTT, i.e. through the untrusted broker. With
auth="unsigned" (attack 6 demo only) the signatures are omitted and a broker
in the middle can substitute its own shares and learn the group key.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securelib.pki import TrustError, raw_public

CONTEXT = b"bbiot-kdc-dh-v1"
KEY_CONTEXT = b"bbiot-kdc-key-v1"
KDC_ID = "kdc"
AUTH_MODES = ("signed", "unsigned")


def _lv(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def transcript(
    device_id: str, eph_d: bytes, nonce_d: bytes, eph_k: bytes, nonce_k: bytes, auth: str
) -> bytes:
    return CONTEXT + b"".join(
        _lv(x)
        for x in (
            device_id.encode(),
            KDC_ID.encode(),
            eph_d,
            nonce_d,
            eph_k,
            nonce_k,
            auth.encode(),
        )
    )


def derive_kek(shared: bytes, nonce_d: bytes, nonce_k: bytes, tx: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_d + nonce_k,
        info=b"bbiot-kdc-kek-v1" + hashlib.sha256(tx).digest(),
    ).derive(shared)


def _dh(priv: X25519PrivateKey, peer_hex: str) -> bytes:
    try:
        return priv.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_hex)))
    except ValueError as exc:  # bad length or low-order point (all-zero secret)
        raise TrustError("invalid ephemeral key") from exc


def _sig_input(role: bytes, tx: bytes) -> bytes:
    return CONTEXT + b"|" + role + b"|" + tx


def wrap_key(kek: bytes, device_id: str, epoch: int, group_key: bytes) -> dict:
    nonce = os.urandom(12)
    a = KEY_CONTEXT + _lv(device_id.encode()) + epoch.to_bytes(4, "big")
    return {
        "t": "key",
        "epoch": epoch,
        "nonce": nonce.hex(),
        "wrapped": AESGCM(kek).encrypt(nonce, group_key, a).hex(),
    }


def unwrap_key(kek: bytes, device_id: str, msg: dict) -> tuple[int, bytes]:
    try:
        epoch = int(msg["epoch"])
        a = KEY_CONTEXT + _lv(device_id.encode()) + epoch.to_bytes(4, "big")
        key = AESGCM(kek).decrypt(bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["wrapped"]), a)
    except (KeyError, ValueError, InvalidTag) as exc:
        raise TrustError("group key could not be unwrapped (wrong session key?)") from exc
    return epoch, key


# --- device side -------------------------------------------------------------------------------


@dataclass
class DeviceJoin:
    device_id: str
    auth: str = "signed"
    eph: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    nonce: bytes = field(default_factory=lambda: os.urandom(16))

    def hello(self) -> dict:
        return {
            "t": "hello",
            "device": self.device_id,
            "eph": raw_public(self.eph.public_key()).hex(),
            "nonce": self.nonce.hex(),
            "auth": self.auth,
        }

    def on_challenge(
        self, msg: dict, kdc_key: Ed25519PublicKey, signer: Ed25519PrivateKey
    ) -> tuple[dict, bytes]:
        """Verify the KDC and return (finish message, KEK)."""
        try:
            eph_k, nonce_k = bytes.fromhex(msg["eph"]), bytes.fromhex(msg["nonce"])
        except (KeyError, ValueError) as exc:
            raise TrustError("malformed challenge") from exc
        tx = transcript(
            self.device_id, raw_public(self.eph.public_key()), self.nonce, eph_k, nonce_k, self.auth
        )
        if self.auth == "signed":
            try:
                kdc_key.verify(bytes.fromhex(msg.get("sig") or ""), _sig_input(b"kdc", tx))
            except (InvalidSignature, ValueError) as exc:
                raise TrustError(
                    "KDC signature invalid — the key exchange was tampered with (MITM?)"
                ) from exc
        kek = derive_kek(_dh(self.eph, msg["eph"]), self.nonce, nonce_k, tx)
        finish = {"t": "finish", "device": self.device_id}
        if self.auth == "signed":
            finish["sig"] = signer.sign(_sig_input(b"device", tx)).hex()
        return finish, kek


# --- KDC side -------------------------------------------------------------------


@dataclass
class KdcJoin:
    device_id: str
    auth: str
    eph_d: bytes
    nonce_d: bytes
    eph: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    nonce: bytes = field(default_factory=lambda: os.urandom(16))

    @classmethod
    def from_hello(cls, msg: dict) -> KdcJoin:
        try:
            auth = msg["auth"]
            if auth not in AUTH_MODES:
                raise ValueError(auth)
            return cls(
                str(msg["device"]), auth, bytes.fromhex(msg["eph"]), bytes.fromhex(msg["nonce"])
            )
        except (KeyError, ValueError) as exc:
            raise TrustError("malformed hello") from exc

    def _tx(self) -> bytes:
        return transcript(
            self.device_id,
            self.eph_d,
            self.nonce_d,
            raw_public(self.eph.public_key()),
            self.nonce,
            self.auth,
        )

    def challenge(self, signer: Ed25519PrivateKey) -> dict:
        msg = {
            "t": "challenge",
            "eph": raw_public(self.eph.public_key()).hex(),
            "nonce": self.nonce.hex(),
        }
        if self.auth == "signed":
            msg["sig"] = signer.sign(_sig_input(b"kdc", self._tx())).hex()
        return msg

    def on_finish(self, msg: dict, device_key: Ed25519PublicKey) -> bytes:
        tx = self._tx()
        if self.auth == "signed":
            try:
                device_key.verify(bytes.fromhex(msg.get("sig") or ""), _sig_input(b"device", tx))
            except (InvalidSignature, ValueError) as exc:
                raise TrustError(
                    f"{self.device_id}'s signature invalid — key exchange tampered with (MITM?)"
                ) from exc
        return derive_kek(_dh(self.eph, self.eph_d.hex()), self.nonce_d, self.nonce, tx)
