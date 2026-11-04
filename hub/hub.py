"""The hub: a commissioned group member that

* runs the MQTT policy gateway (MUD enforcement) in front of the broker
* watches liveness: sequence gaps, heartbeats, unacked alarms → alerts
* acknowledges alarms end to end (signed)
* quarantines policy violators: block at the gateway, signed quarantine
  notice (→ devices distrust it, KDC removes it and rekeys), MLS removal
  (the hub is the MLS group admin), and a remove-device action for the
  admins to confirm the revocation (2 of 3)
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt

from devices.base import DeviceBase
from hub.gateway import PolicyGateway
from hub.monitor import Monitor
from hub.policy import PolicyStore
from hub.quarantine import TOPIC as QUARANTINE_TOPIC
from hub.quarantine import sign_notice
from rootca import approvals
from securelib.message import peek_header


class Hub(DeviceBase):
    kind = "hub"

    def reset_state(self) -> None:
        if not hasattr(self, "quarantined"):
            self.quarantined: dict[str, str] = {}
            self.q_version = int(time.time())  # monotonic across restarts
        self.monitor = Monitor()

    def subscriptions(self) -> list[str]:
        return ["home/#", "hb/+", "ack/+"]

    def set_security(self, mode: str) -> None:
        super().set_security(mode)
        # Sequence numbers keep counting on plaintext (OFF) traffic, which proves
        # nothing; start gap tracking afresh so that isn't mistaken for drops.
        self.monitor = Monitor()

    # --- liveness ----------------------------------------------------------------------------

    def _on_message(self, c: mqtt.Client, u: Any, msg: mqtt.MQTTMessage) -> None:
        if self.own_echo(msg.payload):
            return  # e.g. our own alarm ack on ack/hub
        if self.channel.mode == "on" and msg.topic.startswith(("home/", "hb/", "ack/")):
            h = peek_header(msg.payload) if msg.payload[:1] == b"\x01" else None
            if h is not None:
                for a in self.monitor.on_message(h.sender, h.seq, h.ts_ms):
                    self._raise(a)
        super()._on_message(c, u, msg)

    def handle(self, topic: str, body: dict[str, Any], sender: str | None, seq: int | None) -> None:
        if topic.startswith("hb/") and sender == topic.split("/", 1)[1]:
            for a in self.monitor.on_heartbeat(sender, body):
                self._raise(a)
            return
        alarm_topics = {d.topics.get("alarm") for d in self.cfg.devices.values()}
        if topic in alarm_topics and sender:
            self.log.info(f"🔔 alarm from {sender} (seq {seq}) → signed ack")
            self.live.send_ack(topic, sender, seq, "alarm")

    def tick(self) -> None:
        self.monitor.expect_heartbeats = {
            d for d in self.trust.trusted_peers() if d in self.cfg.devices and d != self.dev.id
        }
        if self.channel.mode == "on":
            for a in self.monitor.tick():
                self._raise(a)

    def _raise(self, a: dict[str, Any]) -> None:
        a = dict(a)
        severity, title = a.pop("severity"), a.pop("title")
        self.log.info(("⚠ " if severity == "critical" else "") + title)
        self.alert(severity, title, title, **a)

    # --- quarantine --------------------------------------------------------------------------

    def quarantine(self, ident: str, reason: str) -> None:
        if ident in self.quarantined or ident == self.dev.id:
            return
        self.quarantined[ident] = reason
        self.log.info(f"🚨 QUARANTINE {ident}: {reason}")
        self._publish_notice()
        if self.gateway is not None:
            self.gateway.disconnect(ident)
        self.trust.set_quarantined(self.quarantined)  # MLS: reconcile removes it (we're admin)
        self.alert(
            "critical",
            f"QUARANTINED {ident}",
            reason,
            device=ident,
            check="MUD policy",
        )
        if ident in self.cfg.devices:
            threading.Thread(target=self._request_revocation, args=(ident,), daemon=True).start()

    def release(self, ident: str) -> bool:
        if self.quarantined.pop(ident, None) is None:
            return False
        self.log.info(f"released {ident} from quarantine")
        self._publish_notice()
        self.trust.set_quarantined(self.quarantined)
        return True

    def _publish_notice(self) -> None:
        self.q_version += 1
        self._publish_json(
            QUARANTINE_TOPIC,
            sign_notice(self.keys.sign_key, self.q_version, self.quarantined),
            retain=True,
        )

    def _request_revocation(self, ident: str) -> None:
        """Revocation needs 2 of 3 admins: post the action and let them decide."""
        try:
            directory = self.trust._verifier_or_build().directory
            if directory.get_cert(ident) is None:
                return
            action = approvals.new_action("remove-device", ident)
            aid = directory.post_action(action, None)["id"]
            self.log.info(
                f"posted revocation request {aid} for {ident} — admins confirm with: "
                f"bbiot admin approve --admin A --action {aid}"
            )
        except Exception as exc:  # noqa: BLE001 - best effort; quarantine already applied
            self.log.info(f"could not post revocation request: {exc}")

    def _on_connect(self, client, u, f, rc, p) -> None:
        super()._on_connect(client, u, f, rc, p)
        if not rc.is_failure:
            self._publish_notice()  # (re)announce the current list

    # --- status + run ------------------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        gw = self.gateway.stats if self.gateway is not None else {}
        return {
            "quarantined": dict(self.quarantined),
            "liveness": self.monitor.status(),
            "gateway": gw,
        }

    gateway: PolicyGateway | None = None

    def start_gateway(self) -> None:
        mud = Path(os.environ.get("BBIOT_MUD_DIR", "config/mud"))
        upstream = (
            os.environ.get("BBIOT_UPSTREAM_HOST", self.cfg.evil_host),
            int(os.environ.get("BBIOT_UPSTREAM_PORT", self.cfg.evil_port)),
        )
        gw = PolicyGateway(
            self.cfg,
            PolicyStore(mud),
            enforcing=lambda: self.channel.mode == "on",
            is_quarantined=lambda ident: ident in self.quarantined,
            on_violation=self.quarantine,
            upstream=upstream,
        )
        self.gateway = gw
        listen = os.environ.get("BBIOT_GATEWAY_LISTEN", "127.0.0.1")
        port = int(os.environ.get("BBIOT_GATEWAY_PORT", "8883"))

        def run() -> None:
            async def main() -> None:
                gw.loop = asyncio.get_running_loop()
                server = await asyncio.start_server(
                    gw.handle, listen, port, ssl=gw.server_context()
                )
                self.log.info(
                    f"policy gateway on {listen}:{port} → broker {upstream[0]}:{upstream[1]} "
                    f"({len(gw.policies.profiles)} MUD profiles)"
                )
                async with server:
                    await server.serve_forever()

            asyncio.run(main())

        threading.Thread(target=run, daemon=True, name="gateway").start()

    def serve_control(self):
        server = super().serve_control()
        hub = self
        handler = server.RequestHandlerClass
        original = handler.do_POST

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path == "/release":
                import json as _json

                length = min(int(self.headers.get("Content-Length") or 0), 4096)
                data = _json.loads(self.rfile.read(length) or b"{}")
                ok = hub.release(str(data.get("device", "")))
                return self._json(200, {"released": ok, "quarantined": hub.quarantined})
            return original(self)

        handler.do_POST = do_POST
        return server

    def run_forever(self) -> None:
        self.start_gateway()
        time.sleep(0.5)
        super().run_forever()
