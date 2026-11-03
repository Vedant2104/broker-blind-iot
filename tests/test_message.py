"""Sealed messages: every receiver check, with the attack it stops."""

from __future__ import annotations

import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from securelib.message import (
    Opener,
    Reject,
    ReplayWindow,
    decrypt_unchecked,
    parse_header,
    peek_header,
    seal,
)

TOPIC = "home/door/front/cmd"
KEY = os.urandom(32)
PHONE = Ed25519PrivateKey.generate()
THERMO = Ed25519PrivateKey.generate()


def now() -> int:
    return int(time.time() * 1000)


def mk(body: bytes = b'{"cmd":"unlock"}', **kw) -> bytes:
    args = dict(
        topic=TOPIC,
        body=body,
        sender="phone",
        seq=1,
        epoch=3,
        group_key=KEY,
        ts_ms=now(),
        signer=PHONE,
    )
    args.update(kw)
    return seal(**args)


def opener(epoch: int = 3, key: bytes = KEY, **kw) -> Opener:
    keys = {"phone": PHONE.public_key(), "thermostat": THERMO.public_key()}
    args = dict(
        group_key_for=lambda e: key if e == epoch else None,
        current_epoch=lambda: epoch,
        sender_key=keys.get,
        requires_signature=lambda t: t.endswith("/cmd"),
    )
    args.update(kw)
    return Opener(**args)


def reason(op: Opener, payload: bytes, topic: str = TOPIC, at: int | None = None) -> str:
    with pytest.raises(Reject) as exc:
        op.open(topic, payload, at or now())
    return exc.value.reason


# --- happy paths ------------------------------------------------------------------------------


@pytest.mark.parametrize("suite", ["AES-GCM", "ChaCha20-Poly1305"])
def test_roundtrip(suite: str) -> None:
    msg = opener().open(TOPIC, mk(suite=suite), now())
    assert (msg.sender, msg.seq, msg.epoch, msg.signed) == ("phone", 1, 3, True)
    assert msg.body == {"cmd": "unlock"} and msg.suite == suite


def test_unsigned_state_update_accepted_on_non_command_topic() -> None:
    t = "home/door/front/state"
    p = mk(b'{"locked":true}', topic=t, signer=None)
    assert opener().open(t, p, now()).signed is False


def test_payload_is_not_readable_by_broker() -> None:
    p = mk(b'{"cmd":"unlock","secret":"sekrit"}')
    assert b"unlock" not in p and b"sekrit" not in p
    h = peek_header(p)
    assert (h.sender, h.seq, h.epoch) == ("phone", 1, 3)  # metadata is visible, by design


def test_nonces_are_fresh() -> None:
    assert parse_header(mk())[0].nonce != parse_header(mk())[0].nonce


# --- attacks ----------------------------------------------------------------------------------


def test_modified_ciphertext_rejected() -> None:
    p = bytearray(mk())
    p[-20] ^= 0x01
    assert reason(opener(), bytes(p)).startswith("tag invalid")


def test_modified_header_rejected() -> None:
    """Changing a clear header field (e.g. bumping seq) breaks the AAD."""
    p = bytearray(mk())
    p[12] ^= 0x01  # inside seq (1 -> 257)
    assert reason(opener(), bytes(p)).startswith("tag invalid")


def test_redirected_topic_rejected() -> None:
    assert reason(opener(), mk(), topic="home/door/back/cmd").startswith("wrong topic")


def test_redirect_with_rewritten_topic_tag_still_fails() -> None:
    from securelib.message import topic_tag

    p = bytearray(mk())
    p[22:26] = topic_tag("home/door/back/cmd")
    assert reason(opener(), bytes(p), topic="home/door/back/cmd").startswith("tag invalid")


def test_replay_rejected() -> None:
    op, p = opener(), mk()
    op.open(TOPIC, p, now())
    r = reason(op, p)
    assert r.startswith("replay (seq 1 already seen")


def test_old_seq_outside_window_rejected() -> None:
    op = opener()
    op.open(TOPIC, mk(seq=100), now())
    assert "too old" in reason(op, mk(seq=10))


def test_out_of_order_inside_window_accepted() -> None:
    op = opener()
    op.open(TOPIC, mk(seq=10), now())
    assert op.open(TOPIC, mk(seq=7), now()).seq == 7


def test_rejected_message_does_not_burn_its_seq() -> None:
    """A forged message with seq 5 must not block the real seq 5 later."""
    op = opener()
    forged = bytearray(mk(seq=5))
    forged[-1] ^= 1
    reason(op, bytes(forged))
    assert op.open(TOPIC, mk(seq=5), now()).seq == 5


def test_stale_timestamp_rejected() -> None:
    old = mk(ts_ms=now() - 60_000)
    assert reason(opener(), old).startswith("stale timestamp")
    future = mk(ts_ms=now() + 60_000)
    assert reason(opener(), future).startswith("stale timestamp")


def test_wrong_epoch_rejected() -> None:
    assert reason(opener(epoch=4), mk(epoch=3)).startswith(
        "wrong epoch (message epoch 3, current 4"
    )


def test_wrong_key_rejected() -> None:
    assert reason(opener(key=os.urandom(32)), mk()).startswith("tag invalid")


def test_insider_forgery_rejected() -> None:
    """Thermostat holds the group key and claims to be the phone."""
    forged = mk(signer=THERMO)
    assert reason(opener(), forged).startswith("bad signature")


def test_unsigned_command_rejected() -> None:
    assert reason(opener(), mk(signer=None)).startswith("unsigned command")


def test_unknown_sender_rejected() -> None:
    p = mk(sender="garage-lock", signer=Ed25519PrivateKey.generate())
    assert reason(opener(), p).startswith("unknown sender")


def test_no_group_key_yet() -> None:
    assert reason(opener(current_epoch=lambda: None), mk()) == "no group key yet"


@pytest.mark.parametrize("payload", [b"", b"\x01\x01", b'{"cmd":"unlock"}', os.urandom(40)])
def test_garbage_rejected(payload: bytes) -> None:
    assert reason(opener(), payload)  # any reason, never an exception


def test_decrypt_unchecked_needs_the_key() -> None:
    assert decrypt_unchecked(TOPIC, mk(), KEY) == b'{"cmd":"unlock"}'
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        decrypt_unchecked(TOPIC, mk(), os.urandom(32))


# --- window unit ------------------------------------------------------------------------------


def test_window_bookkeeping() -> None:
    w = ReplayWindow(size=8)
    for s in (1, 2, 5):
        w.check(s)
        w.commit(s)
    w.check(3)  # gap inside window: fine
    with pytest.raises(Reject):
        w.check(5)
    w.commit(20)
    with pytest.raises(Reject, match="too old"):
        w.check(12)
    w.check(13)
