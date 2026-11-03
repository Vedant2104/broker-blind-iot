"""Attack 6: the broker sits in the middle of a device ↔ KDC key exchange.

It swaps both ephemeral X25519 shares for its own. If the exchange is
unsigned, both ends happily derive a key with the attacker, who then unwraps
the group key and re-wraps it for the device — nobody notices. If the exchange
is signed, the substituted shares break the transcript signature and the
device refuses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from securelib.kdcproto import _dh, derive_kek, transcript, unwrap_key, wrap_key
from securelib.pki import TrustError, raw_public


@dataclass
class DhMitm:
    device_id: str
    a1: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)  # faces the KDC
    a2: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)  # faces the device
    hello: dict | None = None
    kek_kdc: bytes | None = None
    kek_dev: bytes | None = None
    learned: dict[int, bytes] = field(default_factory=dict)  # epoch -> stolen group key
    notes: list[str] = field(default_factory=list)

    def on_hello(self, msg: dict) -> dict:
        self.hello = msg
        self.notes.append(f"swapped device share in hello (auth={msg.get('auth')})")
        return {**msg, "eph": raw_public(self.a1.public_key()).hex()}

    def on_challenge(self, msg: dict) -> dict:
        if self.hello is None:
            return msg
        h = self.hello
        nd, nk = bytes.fromhex(h["nonce"]), bytes.fromhex(msg["nonce"])
        a1_pub, a2_pub = raw_public(self.a1.public_key()), raw_public(self.a2.public_key())
        tx_kdc = transcript(self.device_id, a1_pub, nd, bytes.fromhex(msg["eph"]), nk, h["auth"])
        tx_dev = transcript(self.device_id, bytes.fromhex(h["eph"]), nd, a2_pub, nk, h["auth"])
        self.kek_kdc = derive_kek(_dh(self.a1, msg["eph"]), nd, nk, tx_kdc)
        self.kek_dev = derive_kek(_dh(self.a2, h["eph"]), nd, nk, tx_dev)
        self.notes.append("swapped KDC share in challenge (signature, if any, left as is)")
        return {**msg, "eph": a2_pub.hex()}

    def on_key(self, msg: dict) -> dict:
        if self.kek_kdc is None or self.kek_dev is None:
            return msg
        try:
            epoch, key = unwrap_key(self.kek_kdc, self.device_id, msg)
        except TrustError:
            return msg  # this session isn't ours (e.g. the KDC rejected the finish)
        self.learned[epoch] = key
        self.notes.append(f"unwrapped group key for epoch {epoch} and re-wrapped it for the device")
        return wrap_key(self.kek_dev, self.device_id, epoch, key)
