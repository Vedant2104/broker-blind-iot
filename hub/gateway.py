"""The hub's MQTT policy gateway: every client connects here first.

It is trusted (it runs on the home's LAN gateway) and sits in front of the
untrusted broker. With security ON it checks each PUBLISH topic and SUBSCRIBE
filter against the client's MUD profile (identity = mTLS certificate CN). A
violation is never forwarded: the client is disconnected and quarantined.
Quarantined identities can't reconnect.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import Callable
from contextlib import suppress

from evilbroker.wire import (
    CONNECT,
    PUBLISH,
    SUBACK_FAILURE,
    SUBSCRIBE,
    MalformedPacket,
    PacketReader,
    connect_protocol_level,
    encode_puback,
    encode_suback,
    packet_type,
    parse_publish,
    parse_subscribe,
)
from hub.policy import PolicyStore
from securelib.config import Config
from securelib.log import get_logger
from securelib.tls import client_paths

log = get_logger("hub/gateway")


def _peer_cn(writer: asyncio.StreamWriter) -> str:
    cert = writer.get_extra_info("peercert") or {}
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return "?"


class PolicyGateway:
    def __init__(
        self,
        cfg: Config,
        policies: PolicyStore,
        *,
        enforcing: Callable[[], bool],
        is_quarantined: Callable[[str], bool],
        on_violation: Callable[[str, str], None],
        upstream: tuple[str, int],
    ) -> None:
        self.cfg = cfg
        self.policies = policies
        self.enforcing = enforcing
        self.is_quarantined = is_quarantined
        self.on_violation = on_violation
        self.upstream = upstream
        self.writers: dict[str, set[asyncio.StreamWriter]] = {}
        self.stats = {"connections": 0, "blocked_packets": 0, "refused_connections": 0}
        self._last_refusal_log: dict[str, float] = {}
        self.loop: asyncio.AbstractEventLoop | None = None

    # --- TLS ---------------------------------------------------------------------------------

    def server_context(self) -> ssl.SSLContext:
        p = client_paths(self.cfg.tls_dir, "hub")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(p.ca))
        ctx.load_cert_chain(p.cert, p.key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def upstream_context(self) -> ssl.SSLContext:
        p = client_paths(self.cfg.tls_dir, "hub")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(p.ca))
        ctx.load_cert_chain(p.cert, p.key)
        return ctx

    # --- quarantine --------------------------------------------------------------------------

    def disconnect(self, ident: str) -> None:
        """Cut every connection of a quarantined identity (thread-safe)."""
        if self.loop is None:
            return

        def _close() -> None:
            for w in list(self.writers.get(ident, ())):
                w.close()

        self.loop.call_soon_threadsafe(_close)

    # --- proxying ----------------------------------------------------------------------------

    async def handle(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        cn = _peer_cn(c_writer)
        if self.enforcing() and self.is_quarantined(cn):
            self.stats["refused_connections"] += 1
            now = time.monotonic()
            if now - self._last_refusal_log.get(cn, 0) > 15:
                self._last_refusal_log[cn] = now
                log.info(f"✗ refused connection from QUARANTINED '{cn}'")
            c_writer.close()
            return
        try:
            u_reader, u_writer = await asyncio.open_connection(
                *self.upstream, ssl=self.upstream_context(), server_hostname="broker"
            )
        except OSError as exc:
            log.info(f"upstream broker unreachable for {cn}: {exc}")
            c_writer.close()
            return
        self.stats["connections"] += 1
        self.writers.setdefault(cn, set()).add(c_writer)
        session = {"v5": False}

        async def client_to_broker() -> None:
            reader = PacketReader()
            while data := await c_reader.read(65536):
                for raw in reader.feed(data):
                    out = self._check(cn, raw, session, c_writer)
                    if out is None:
                        return  # violation: stop forwarding, connection is closed
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
            self.writers.get(cn, set()).discard(c_writer)
            for w in (u_writer, c_writer):
                w.close()

    def _check(
        self, cn: str, raw: bytes, session: dict, c_writer: asyncio.StreamWriter
    ) -> bytes | None:
        kind = packet_type(raw)
        if kind == CONNECT:
            session["v5"] = connect_protocol_level(raw) == 5
            return raw
        if not self.enforcing() or kind not in (PUBLISH, SUBSCRIBE):
            return raw

        profile = self.policies.get(cn)
        if kind == PUBLISH:
            pub = parse_publish(raw, session["v5"])
            problem = profile.check_publish(pub.topic)
            if problem is None:
                return raw
            if pub.qos == 1 and pub.packet_id is not None:
                c_writer.write(encode_puback(pub.packet_id))
        else:
            sub = parse_subscribe(raw, session["v5"])
            problems = [p for f, _ in sub.filters if (p := profile.check_subscribe(f))]
            if not problems:
                return raw
            codes = [SUBACK_FAILURE] * len(sub.filters)
            c_writer.write(encode_suback(sub.packet_id, codes, session["v5"]))
            problem = problems[0]

        self.stats["blocked_packets"] += 1
        log.info(f"✗ BLOCKED '{cn}': {problem}")
        c_writer.close()
        self.on_violation(cn, problem)
        return None
