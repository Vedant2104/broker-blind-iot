from __future__ import annotations

import json

from evilbroker.rules import CaptureStore, Rules, extract_seq, tamper_payload
from evilbroker.wire import Publish

CMD = Publish(topic="home/door/front/cmd", payload=b'{"from":"phone","seq":4,"cmd":"unlock"}')


def test_no_rules_passes_through() -> None:
    assert Rules().apply(CMD) == (CMD, None)


def test_drop() -> None:
    rules = Rules(drop={CMD.topic})
    out, note = rules.apply(CMD)
    assert out is None and "DROPPED" in note


def test_redirect_changes_topic_only() -> None:
    rules = Rules(redirect={CMD.topic: "home/door/back/cmd"})
    out, note = rules.apply(CMD)
    assert out.topic == "home/door/back/cmd"
    assert out.payload == CMD.payload
    assert "REDIRECTED" in note


def test_modify_rewrites_readable_setpoint() -> None:
    p = Publish(topic="t", payload=b'{"cmd":"set","setpoint":21.0}')
    out, note = Rules(modify={"t": 30.0}).apply(p)
    assert json.loads(out.payload)["setpoint"] == 30.0
    assert "21.0 -> 30.0" in note


def test_modify_flips_a_bit_in_unreadable_payload() -> None:
    ciphertext = bytes(range(32))
    tampered, what = tamper_payload(ciphertext, 30.0)
    assert tampered != ciphertext and len(tampered) == len(ciphertext)
    assert sum(a != b for a, b in zip(tampered, ciphertext, strict=True)) == 1
    assert "flipped" in what


def test_extract_seq() -> None:
    assert extract_seq(CMD.payload) == 4
    assert extract_seq(b"\x00\x01binary") is None
    assert extract_seq(b'{"seq":"7"}') is None


def test_capture_store_find_by_topic_and_seq() -> None:
    store = CaptureStore(maxlen=3)
    for _ in range(5):
        store.add("phone", CMD)
    assert len(store.find()) == 3  # ring buffer
    assert [c.seq for c in store.find(topic=CMD.topic, seq=4)] == [4, 4, 4]
    assert store.find(seq=99) == []
    last = store.find()[-1]
    assert store.get(last.id) == last
    assert "payload" not in last.summary()
