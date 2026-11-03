"""Device ↔ KDC key exchange, honest and through a man-in-the-middle broker."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evilbroker.mitm_dh import DhMitm
from securelib.kdcproto import DeviceJoin, KdcJoin, unwrap_key, wrap_key
from securelib.pki import TrustError

DEV_KEY = Ed25519PrivateKey.generate()
KDC_KEY = Ed25519PrivateKey.generate()
GROUP = os.urandom(32)


def run(auth: str, mitm: DhMitm | None = None, kdc_auth_ok: bool = True):
    """Full exchange; returns (device KEK, KDC KEK, key the device ends up with)."""
    dev = DeviceJoin("thermostat", auth=auth)
    hello = dev.hello()
    if mitm:
        hello = mitm.on_hello(hello)
    kdc = KdcJoin.from_hello(hello)
    challenge = kdc.challenge(KDC_KEY)
    if mitm:
        challenge = mitm.on_challenge(challenge)
    finish, kek_dev = dev.on_challenge(challenge, KDC_KEY.public_key(), DEV_KEY)
    kek_kdc = kdc.on_finish(finish, DEV_KEY.public_key())
    key_msg = wrap_key(kek_kdc, "thermostat", 7, GROUP)
    if mitm:
        key_msg = mitm.on_key(key_msg)
    return kek_dev, kek_kdc, unwrap_key(kek_dev, "thermostat", key_msg)


@pytest.mark.parametrize("auth", ["signed", "unsigned"])
def test_honest_exchange_delivers_group_key(auth: str) -> None:
    kek_dev, kek_kdc, (epoch, key) = run(auth)
    assert kek_dev == kek_kdc and (epoch, key) == (7, GROUP)


def test_unsigned_exchange_is_broken_by_mitm() -> None:
    """Attack 6 with security OFF: the broker learns the group key, unnoticed."""
    mitm = DhMitm("thermostat")
    kek_dev, kek_kdc, (epoch, key) = run("unsigned", mitm)
    assert key == GROUP  # device got the right key — no error anywhere
    assert kek_dev != kek_kdc  # ...but each end shares its KEK with the attacker
    assert mitm.learned == {7: GROUP}


def test_signed_exchange_detects_mitm() -> None:
    """Attack 6 with security ON: the device refuses the tampered challenge."""
    with pytest.raises(TrustError, match="KDC signature invalid"):
        run("signed", DhMitm("thermostat"))


def test_kdc_detects_tampered_device_share() -> None:
    """Even if a device skipped its own check, the KDC refuses: the device signed
    its real share, the KDC saw the attacker's."""
    from securelib.kdcproto import _sig_input, transcript
    from securelib.pki import raw_public

    dev = DeviceJoin("thermostat")
    kdc = KdcJoin.from_hello(DhMitm("thermostat").on_hello(dev.hello()))
    ch = kdc.challenge(KDC_KEY)
    tx_dev = transcript(
        "thermostat",
        raw_public(dev.eph.public_key()),
        dev.nonce,
        bytes.fromhex(ch["eph"]),
        bytes.fromhex(ch["nonce"]),
        "signed",
    )
    finish = {"t": "finish", "sig": DEV_KEY.sign(_sig_input(b"device", tx_dev)).hex()}
    with pytest.raises(TrustError, match="signature invalid"):
        kdc.on_finish(finish, DEV_KEY.public_key())


def test_challenge_signed_by_other_key_rejected() -> None:
    dev = DeviceJoin("thermostat")
    kdc = KdcJoin.from_hello(dev.hello())
    with pytest.raises(TrustError):
        dev.on_challenge(kdc.challenge(Ed25519PrivateKey.generate()), KDC_KEY.public_key(), DEV_KEY)


def test_downgrade_to_unsigned_rejected() -> None:
    """Broker rewrites auth=signed to unsigned: the device still expects a signature."""
    dev = DeviceJoin("thermostat", auth="signed")
    kdc = KdcJoin.from_hello({**dev.hello(), "auth": "unsigned"})
    with pytest.raises(TrustError):
        dev.on_challenge(kdc.challenge(KDC_KEY), KDC_KEY.public_key(), DEV_KEY)


def test_identity_misbinding_rejected() -> None:
    """A hello relabelled as another device changes the signed transcript."""
    dev = DeviceJoin("thermostat")
    kdc = KdcJoin.from_hello({**dev.hello(), "device": "front-door"})
    with pytest.raises(TrustError):
        dev.on_challenge(kdc.challenge(KDC_KEY), KDC_KEY.public_key(), DEV_KEY)


def test_key_wrapped_for_other_device_or_epoch_rejected() -> None:
    kek = os.urandom(32)
    msg = wrap_key(kek, "thermostat", 3, GROUP)
    with pytest.raises(TrustError):
        unwrap_key(kek, "front-door", msg)
    with pytest.raises(TrustError):
        unwrap_key(kek, "thermostat", {**msg, "epoch": 4})
    with pytest.raises(TrustError):
        unwrap_key(os.urandom(32), "thermostat", msg)


def test_bad_ephemeral_rejected() -> None:
    dev = DeviceJoin("thermostat")
    kdc = KdcJoin.from_hello(dev.hello())
    challenge = {**kdc.challenge(KDC_KEY), "eph": "00" * 32}  # low-order point
    with pytest.raises(TrustError):
        DeviceJoin("thermostat", auth="unsigned").on_challenge(
            challenge, KDC_KEY.public_key(), DEV_KEY
        )
