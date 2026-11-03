from __future__ import annotations

import pytest

from evilbroker.wire import (
    CONNECT,
    PUBLISH,
    MalformedPacket,
    PacketReader,
    Publish,
    connect_protocol_level,
    decode_varint,
    encode_puback,
    encode_publish,
    encode_varint,
    packet_type,
    parse_publish,
)


@pytest.mark.parametrize("n", [0, 1, 127, 128, 16_383, 16_384, 2_097_151, 268_435_455])
def test_varint_roundtrip(n: int) -> None:
    enc = encode_varint(n)
    assert decode_varint(enc, 0) == (n, len(enc))


def test_varint_rejects_five_bytes() -> None:
    with pytest.raises(MalformedPacket):
        decode_varint(b"\xff\xff\xff\xff\x01", 0)


def test_varint_incomplete_returns_none() -> None:
    assert decode_varint(b"\x80", 0) is None


@pytest.mark.parametrize("v5", [False, True])
@pytest.mark.parametrize("qos", [0, 1])
def test_publish_roundtrip(v5: bool, qos: int) -> None:
    p = Publish(
        topic="home/door/front/cmd",
        payload=b'{"cmd":"unlock"}',
        qos=qos,
        retain=True,
        packet_id=7 if qos else None,
        properties=b"\x00" if v5 else b"",
    )
    raw = encode_publish(p, v5)
    assert packet_type(raw) == PUBLISH
    assert parse_publish(raw, v5) == p


def test_v5_properties_kept_verbatim() -> None:
    props = b"\x03\x01\x01\x00"  # length 3: payload-format-indicator=1, then a stray byte
    p = Publish(topic="t", payload=b"x", qos=1, packet_id=1, properties=props)
    assert parse_publish(encode_publish(p, True), True).properties == props


def test_reader_handles_split_and_coalesced_packets() -> None:
    a = encode_publish(Publish(topic="a", payload=b"1" * 300), False)
    b = encode_publish(Publish(topic="b", payload=b"2"), False)
    stream = a + b
    reader = PacketReader()
    out = []
    for i in range(0, len(stream), 7):  # feed in small chunks
        out += reader.feed(stream[i : i + 7])
    assert out == [a, b]


def test_reader_rejects_oversized_packet() -> None:
    with pytest.raises(MalformedPacket):
        PacketReader().feed(bytes([PUBLISH << 4]) + encode_varint(50_000_000))


def test_connect_protocol_level() -> None:
    body = b"\x00\x04MQTT\x05\x02\x00\x3c"
    raw = bytes([CONNECT << 4]) + encode_varint(len(body)) + body
    assert connect_protocol_level(raw) == 5


def test_puback() -> None:
    assert encode_puback(513) == b"\x40\x02\x02\x01"


def test_qos3_rejected() -> None:
    raw = bytes([PUBLISH << 4 | 0b0110]) + b"\x03\x00\x01t"
    with pytest.raises(MalformedPacket):
        parse_publish(raw, False)
