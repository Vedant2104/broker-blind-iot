"""Minimal MQTT wire format: split a byte stream into packets, parse and
re-encode PUBLISH. Supports MQTT 3.1, 3.1.1 and 5 (v5 properties are kept
as opaque bytes). Only what the proxy needs — not a general MQTT library."""

from __future__ import annotations

from dataclasses import dataclass, replace

CONNECT, PUBLISH, PUBACK = 1, 3, 4
MAX_PACKET = 1 << 20  # refuse absurd sizes from either side


class MalformedPacket(ValueError):
    pass


def encode_varint(n: int) -> bytes:
    if not 0 <= n <= 268_435_455:
        raise MalformedPacket(f"remaining length out of range: {n}")
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def decode_varint(buf: bytes | bytearray, pos: int) -> tuple[int, int] | None:
    """Return (value, next_pos), or None if more bytes are needed."""
    value, shift = 0, 0
    for i in range(4):
        if pos + i >= len(buf):
            return None
        byte = buf[pos + i]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos + i + 1
        shift += 7
    raise MalformedPacket("remaining length longer than 4 bytes")


class PacketReader:
    """Feed raw bytes, get back complete raw packets."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf += data
        packets: list[bytes] = []
        while len(self._buf) >= 2:
            decoded = decode_varint(self._buf, 1)
            if decoded is None:
                break
            length, start = decoded
            if length > MAX_PACKET:
                raise MalformedPacket(f"packet too large: {length}")
            end = start + length
            if len(self._buf) < end:
                break
            packets.append(bytes(self._buf[:end]))
            del self._buf[:end]
        return packets


def packet_type(raw: bytes) -> int:
    return raw[0] >> 4


def _body(raw: bytes) -> bytes:
    decoded = decode_varint(raw, 1)
    if decoded is None:
        raise MalformedPacket("truncated header")
    return raw[decoded[1] :]


def connect_protocol_level(raw: bytes) -> int:
    """Protocol level from a CONNECT packet: 3 (v3.1), 4 (v3.1.1) or 5."""
    body = _body(raw)
    name_len = int.from_bytes(body[0:2], "big")
    return body[2 + name_len]


@dataclass(frozen=True)
class Publish:
    topic: str
    payload: bytes
    qos: int = 0
    retain: bool = False
    dup: bool = False
    packet_id: int | None = None
    properties: bytes = b""  # v5 only: property-length varint + properties, verbatim

    def with_(self, **changes: object) -> Publish:
        return replace(self, **changes)  # type: ignore[arg-type]


def parse_publish(raw: bytes, v5: bool) -> Publish:
    flags = raw[0] & 0x0F
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise MalformedPacket("invalid QoS 3")
    body = _body(raw)
    topic_len = int.from_bytes(body[0:2], "big")
    pos = 2 + topic_len
    if pos > len(body):
        raise MalformedPacket("topic overruns packet")
    topic = body[2:pos].decode("utf-8")
    packet_id = None
    if qos:
        packet_id = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
    props = b""
    if v5:
        decoded = decode_varint(body, pos)
        if decoded is None:
            raise MalformedPacket("truncated v5 properties")
        plen, after = decoded
        props = body[pos : after + plen]
        pos = after + plen
    return Publish(
        topic=topic,
        payload=body[pos:],
        qos=qos,
        retain=bool(flags & 0x01),
        dup=bool(flags & 0x08),
        packet_id=packet_id,
        properties=props,
    )


def encode_publish(p: Publish, v5: bool) -> bytes:
    topic = p.topic.encode("utf-8")
    body = bytearray(len(topic).to_bytes(2, "big") + topic)
    if p.qos:
        if p.packet_id is None:
            raise MalformedPacket("QoS>0 publish needs a packet id")
        body += p.packet_id.to_bytes(2, "big")
    if v5:
        body += p.properties or b"\x00"
    body += p.payload
    flags = (0x08 if p.dup else 0) | (p.qos << 1) | (0x01 if p.retain else 0)
    return bytes([PUBLISH << 4 | flags]) + encode_varint(len(body)) + bytes(body)


def encode_puback(packet_id: int) -> bytes:
    """PUBACK with success (valid for v3.1.1 and v5: reason code may be omitted)."""
    return bytes([PUBACK << 4, 2]) + packet_id.to_bytes(2, "big")


# --- SUBSCRIBE / SUBACK (used by the hub's policy gateway) ---------------------------------

SUBSCRIBE, SUBACK = 8, 9
SUBACK_FAILURE = 0x80  # v3.1.1 "failure"; v5 "unspecified error"


@dataclass(frozen=True)
class Subscribe:
    packet_id: int
    filters: list[tuple[str, int]]  # (topic filter, options byte)
    properties: bytes = b""


def parse_subscribe(raw: bytes, v5: bool) -> Subscribe:
    body = _body(raw)
    packet_id = int.from_bytes(body[0:2], "big")
    pos, props = 2, b""
    if v5:
        decoded = decode_varint(body, pos)
        if decoded is None:
            raise MalformedPacket("truncated v5 properties")
        plen, after = decoded
        props = body[pos : after + plen]
        pos = after + plen
    filters = []
    while pos < len(body):
        n = int.from_bytes(body[pos : pos + 2], "big")
        if pos + 2 + n + 1 > len(body):
            raise MalformedPacket("subscription overruns packet")
        filters.append((body[pos + 2 : pos + 2 + n].decode("utf-8"), body[pos + 2 + n]))
        pos += 3 + n
    if not filters:
        raise MalformedPacket("SUBSCRIBE without topic filters")
    return Subscribe(packet_id, filters, props)


def encode_subscribe(s: Subscribe, v5: bool) -> bytes:
    body = bytearray(s.packet_id.to_bytes(2, "big"))
    if v5:
        body += s.properties or b"\x00"
    for flt, opts in s.filters:
        b = flt.encode("utf-8")
        body += len(b).to_bytes(2, "big") + b + bytes([opts])
    return bytes([SUBSCRIBE << 4 | 0x02]) + encode_varint(len(body)) + bytes(body)


def encode_suback(packet_id: int, codes: list[int], v5: bool) -> bytes:
    body = packet_id.to_bytes(2, "big") + (b"\x00" if v5 else b"") + bytes(codes)
    return bytes([SUBACK << 4]) + encode_varint(len(body)) + body
