from __future__ import annotations

import json

import pytest

from securelib.channel import Channel


def test_off_mode_roundtrip_and_sequence() -> None:
    ch = Channel("phone")
    p1 = ch.seal("home/door/front/cmd", {"cmd": "unlock"})
    p2 = ch.seal("home/door/front/cmd", {"cmd": "lock"})
    o1, o2 = ch.open("t", p1), ch.open("t", p2)
    assert (o1.ok, o1.sender, o1.seq, o1.body) == (True, "phone", 1, {"cmd": "unlock"})
    assert o2.seq == 2


def test_off_mode_is_readable_by_anyone() -> None:
    """The baseline: payloads are plaintext JSON (this is what attack 1 exploits)."""
    payload = Channel("phone").seal("t", {"cmd": "unlock"})
    assert json.loads(payload)["cmd"] == "unlock"


def test_off_mode_accepts_forged_sender() -> None:
    """Nothing is authenticated in mode=off — a forged envelope is accepted."""
    forged = json.dumps({"from": "phone", "seq": 1, "cmd": "unlock"}).encode()
    assert Channel("front-door").open("t", forged).ok


@pytest.mark.parametrize("payload", [b"\xff\xfe", b"not json", b"[1,2]"])
def test_malformed_rejected(payload: bytes) -> None:
    opened = Channel("x").open("t", payload)
    assert not opened.ok and "malformed" in opened.reason


def test_unknown_mode_refused() -> None:
    with pytest.raises(ValueError):
        Channel("x", mode="on")  # until phase 3
