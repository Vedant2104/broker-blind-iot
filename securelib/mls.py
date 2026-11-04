"""Decentralized group keys: MLS (RFC 9420) via the OpenMLS sidecar.

Each device runs its own `bbiot-mls` subprocess; MLS secrets stay in it. The
directory serves only public material (certificates, key packages) and stores
handshake messages (commits, welcomes) as an untrusted delivery service. The
group key for the message layer is the MLS exporter output for the current epoch.

Rules enforced here, on every device:
  * the MLS signature key of every member must equal that device's certified
    Ed25519 key (root ✓, log ✓, pin ✓) — a substituted key package is refused
  * only the configured group admin may commit (add/remove)
  * a key derived from an epoch whose membership doesn't verify is never used
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securelib.log import get_logger
from securelib.pki import raw_public
from securelib.services import ServiceError

EXPORT_LABEL = "bbiot-group-key-v1"
COMMIT_TOPIC = "mls/commit"
WELCOME_TOPIC = "mls/welcome"
REJOIN_TOPIC = "mls/rejoin"
REJOIN_CONTEXT = b"bbiot-mls-rejoin-v1"


class MlsError(RuntimeError):
    pass


def find_binary() -> str | None:
    return os.environ.get("BBIOT_MLS_BIN") or shutil.which("bbiot-mls")


class MlsSidecar:
    """JSON-lines client for one bbiot-mls subprocess."""

    def __init__(self, binary: str | None = None) -> None:
        path = binary or find_binary()
        if not path:
            raise MlsError("bbiot-mls binary not found (set BBIOT_MLS_BIN)")
        self.proc = subprocess.Popen(  # noqa: S603 - fixed binary, no shell
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def call(self, cmd: str, **args: Any) -> dict:
        with self._lock:
            req = {"id": next(self._ids), "cmd": cmd, **args}
            assert self.proc.stdin and self.proc.stdout  # noqa: S101
            self.proc.stdin.write(json.dumps(req) + "\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
        if not line:
            raise MlsError("MLS sidecar exited")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise MlsError(reply.get("error", "unknown error"))
        return reply["result"]

    def close(self) -> None:
        self.proc.kill()


def sign_rejoin(key: Ed25519PrivateKey, device: str, ts_ms: int) -> str:
    return key.sign(REJOIN_CONTEXT + device.encode() + ts_ms.to_bytes(8, "big")).hex()


def verify_rejoin(pub: Ed25519PublicKey, device: str, ts_ms: int, sig_hex: str) -> bool:
    try:
        pub.verify(
            bytes.fromhex(sig_hex), REJOIN_CONTEXT + device.encode() + ts_ms.to_bytes(8, "big")
        )
        return True
    except (InvalidSignature, ValueError):
        return False


class DecentralizedGroupKeys:
    """GroupKeys implementation backed by MLS."""

    mode = "decentralized"

    def __init__(
        self,
        device_id: str,
        sign_key: Ed25519PrivateKey,
        admin_id: str,
        *,
        publish: Callable[[str, dict], None],
        certified_key: Callable[[str], Ed25519PublicKey | None],
        directory: Any,  # DirectoryClient-like: mls_* methods
        on_alert: Callable[[str, str, str], None],
        trusted_peers: Callable[[], list[str]] = list,
        refresh_trust: Callable[[], None] = lambda: None,
        sidecar: MlsSidecar | None = None,
    ) -> None:
        self.device_id = device_id
        self.sign_key = sign_key
        self.admin_id = admin_id
        self.publish = publish
        self.certified_key = certified_key
        self.directory = directory
        self.on_alert = on_alert
        self.trusted_peers = trusted_peers
        self.refresh_trust = refresh_trust
        self.log = get_logger("securelib")
        self._pending: dict | None = None  # epoch refused until its members verify
        self._last_problem: str | None = None
        self._lock = threading.RLock()
        self.mls = sidecar or MlsSidecar()
        self.mls.call(
            "init",
            identity=device_id,
            sig_priv=sign_key.private_bytes_raw().hex(),
            sig_pub=raw_public(sign_key.public_key()).hex(),
        )
        self._group: dict | None = None  # last members() result
        self._valid_epoch: int | None = None
        self._key: tuple[int, bytes] | None = None
        self._kp_published = False
        self._kp_published_at = 0.0
        self._last_rejoin = 0.0
        self._used_kps: set[str] = set()  # admin: key packages already used (single-use)
        self._added_at: dict[str, float] = {}  # admin: when each device was last (re-)added
        self.last_commit_ms: float | None = None

    @property
    def is_admin(self) -> bool:
        return self.device_id == self.admin_id

    # --- GroupKeys interface ----------------------------------------------------------

    def current(self) -> tuple[int, bytes] | None:
        with self._lock:
            return self._key

    def key_for(self, epoch: int) -> bytes | None:
        with self._lock:
            return self._key[1] if self._key and self._key[0] == epoch else None

    @property
    def epoch(self) -> int | None:
        k = self._key
        return k[0] if k else None

    def subscriptions(self) -> list[str]:
        subs = [COMMIT_TOPIC, WELCOME_TOPIC]
        if self.is_admin:
            subs.append(f"{REJOIN_TOPIC}/+")
        return subs

    def status(self) -> dict[str, Any]:
        g = self._group or {}
        return {
            "mode": self.mode,
            "epoch": self.epoch,
            "admin": self.admin_id,
            "members": [m["identity"] for m in g.get("members", [])],
            "group_id": (g.get("group_id") or "")[:16] or None,
        }

    # --- membership verification ----------------------------------------------------------

    def _verify_members(self, info: dict) -> str | None:
        """None if every MLS member's signature key is that device's certified key."""
        names = [m["identity"] for m in info["members"]]
        if self.admin_id not in names:
            return f"group does not contain the admin '{self.admin_id}'"
        for m in info["members"]:
            ident = m["identity"]
            if ident == self.device_id:
                expected = raw_public(self.sign_key.public_key()).hex()
            else:
                pub = self.certified_key(ident)
                if pub is None:
                    return f"member '{ident}' has no verified certificate"
                expected = raw_public(pub).hex()
            if m["signature_key"] != expected:
                return f"member '{ident}' uses a key that is NOT its certified key"
        return None

    def _install(self, info: dict, how: str) -> None:
        """Adopt a new epoch only if its membership verifies against the PKI."""
        problem = self._verify_members(info)
        with self._lock:
            self._group = info
        if problem:
            self._pending = info
            if problem != self._last_problem:
                self._last_problem = problem
                self.log.info(f"✗ MLS epoch {info['epoch']} REFUSED (for now): {problem}")
                self.on_alert("critical", f"{self.device_id}: MLS group refused", problem)
            if "no verified certificate" in problem:
                self.refresh_trust()  # maybe our view of that peer is just out of date
            return
        if self._pending is not None:
            self.log.info(f"MLS epoch {info['epoch']} now verifies — accepting it")
        self._pending, self._last_problem = None, None
        secret = self.mls.call("export", label=EXPORT_LABEL, length=32)
        with self._lock:
            self._key = (int(secret["epoch"]), bytes.fromhex(secret["secret"]))
            self._valid_epoch = int(secret["epoch"])
        names = ", ".join(m["identity"] for m in info["members"])
        self.log.info(
            f"MLS epoch={info['epoch']} installed ({how}); {len(info['members'])} members [{names}]"
        )

    # --- handshake processing ---------------------------------------------------------------

    def handle(self, topic: str, payload: bytes) -> None:
        try:
            msg = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return
        with self._lock:
            self._handle(topic, msg)

    def _handle(self, topic: str, msg: dict) -> None:
        try:
            if topic == WELCOME_TOPIC:
                self._on_welcome(msg)
            elif topic == COMMIT_TOPIC:
                self._on_commit(msg)
            elif topic.startswith(REJOIN_TOPIC + "/") and self.is_admin:
                self._on_rejoin(topic.rsplit("/", 1)[1], msg)
        except MlsError as exc:
            self.log.info(f"✗ MLS {topic}: {exc}")
        except ServiceError as exc:  # directory slow or down: retried on the next request
            self.log.info(f"✗ MLS {topic}: {exc}")

    def _on_welcome(self, msg: dict) -> None:
        if self.device_id not in msg.get("to", []):
            return
        with self._lock:
            mine = (self._group or {}).get("group_id")
            my_epoch = int((self._group or {}).get("epoch", -1))
        # Same group and we're current: nothing to do. But a welcome for a NEWER epoch of
        # our own group means we were removed and re-added while offline — take it.
        same_group = mine == msg.get("group_id") and self._key is not None
        if same_group and int(msg.get("epoch", -1)) <= my_epoch:
            return
        info = self.mls.call("welcome", welcome=msg["welcome"])
        self._kp_published = False  # key package consumed — publish a fresh one
        self._install(info, f"joined via welcome from {self.admin_id}")

    def _on_commit(self, msg: dict) -> None:
        with self._lock:
            g = self._group
        if self.is_admin or g is None or msg.get("group_id") != g.get("group_id"):
            return
        if int(msg.get("epoch", -1)) <= int(g["epoch"]):
            return  # already have it
        if int(msg["epoch"]) > int(g["epoch"]) + 1:
            self.catch_up()
            return
        self._apply_commit(msg)

    def _apply_commit(self, msg: dict) -> None:
        try:
            info = self.mls.call("commit", commit=msg["commit"], expected_committer=self.admin_id)
        except MlsError as exc:
            self.log.info(f"✗ MLS commit REFUSED: {exc}")
            if "refused" in str(exc):
                self.on_alert("critical", f"{self.device_id}: unauthorised MLS commit", str(exc))
            return
        if info.get("removed"):
            with self._lock:
                self._group, self._key = None, None
            self.log.info("removed from the MLS group by the admin — no further group keys")
            return
        self._install(info, f"commit by {info.get('committer')}")

    def catch_up(self) -> None:
        """Fetch handshake messages we missed (e.g. dropped by the broker) from the
        directory's delivery service and apply them in order."""
        with self._lock:
            g = self._group
        if g is None:
            return
        for msg in self.directory.mls_handshakes(g["group_id"], after=int(g["epoch"])):
            if msg.get("kind") == "commit":
                self._apply_commit(msg)

    # --- key packages + rejoin ----------------------------------------------------------------

    def publish_key_package(self) -> None:
        kp = self.mls.call("key_package")["key_package"]
        self.directory.mls_put_key_package(self.device_id, kp)
        self._kp_published = True
        self._kp_published_at = time.monotonic()
        self.log.info("published a fresh MLS key package to the directory")

    def request_rejoin(self, force: bool = False) -> None:
        """Ask the admin to (re-)add us. ``force`` declares our MLS state lost, so the
        admin re-adds us even if we look up to date."""
        now = time.monotonic()
        if self.is_admin:
            return
        # Give the admin's own reconcile loop a chance first, then ask (rate-limited).
        if not force and (now - self._kp_published_at < 15 or now - self._last_rejoin < 10):
            return
        self._last_rejoin = time.monotonic()
        # Key packages are single-use and the admin may already have spent our last one
        # (e.g. on a welcome we never received): always offer a fresh one with the request.
        try:
            self.publish_key_package()
        except Exception as exc:  # noqa: BLE001 - directory trouble: the request may still help
            self.log.info(f"could not publish a fresh key package: {exc}")
        ts = int(time.time() * 1000)
        self.publish(
            f"{REJOIN_TOPIC}/{self.device_id}",
            {
                "ts": ts,
                "sig": sign_rejoin(self.sign_key, self.device_id, ts),
                "epoch": None if force else self.epoch,
                "force": force,
            },
        )
        self.log.info(f"asked {self.admin_id} to (re-)add me to the MLS group")

    def _on_rejoin(self, device: str, msg: dict) -> None:
        pub = self.certified_key(device)
        ts = int(msg.get("ts", 0))
        if pub is None or abs(time.time() * 1000 - ts) > 30_000:
            self.log.info(f"rejoin from {device} ignored: no verified certificate or stale")
            return
        if not verify_rejoin(pub, device, ts, str(msg.get("sig", ""))):
            self.log.info(f"✗ forged MLS rejoin request for {device} ignored")
            return
        with self._lock:
            members = {m["identity"] for m in (self._group or {}).get("members", [])}
            current = (self._group or {}).get("epoch")
        if not msg.get("force"):
            if device in members and msg.get("epoch") is not None and msg.get("epoch") == current:
                return  # it is up to date after all
            if time.monotonic() - self._added_at.get(device, 0.0) < 8:
                return  # just (re-)added it; its welcome is probably still in flight
        kp = self.directory.mls_get_key_package(device)
        if kp is None or kp in self._used_kps:
            self.log.info(f"rejoin from {device}: waiting for a fresh key package")
            return
        if device in members:
            self._commit_remove([device], reason=f"{device} lost its MLS state")
        self._add([device])

    # --- admin: reconcile membership with the PKI ----------------------------------------------

    def tick(self) -> None:
        with self._lock:
            self._tick()

    def _tick(self) -> None:
        if self._pending is not None:
            try:  # re-check a refused epoch once our trust view has caught up
                self._install(self.mls.call("members"), "re-verified")
            except MlsError:
                self._pending = None
        try:
            if not self._kp_published and not self.is_admin:
                self.publish_key_package()
            if self.is_admin:
                self.reconcile()
            elif self._key is None:
                self.request_rejoin()
        except MlsError as exc:
            self.log.info(f"MLS: {exc}")
        except Exception as exc:  # noqa: BLE001 - directory/network trouble: retry next tick
            self.log.info(f"MLS: {type(exc).__name__}: {exc}")

    def _broadcast(self, kind: str, info: dict, data: str, to: list[str] | None = None) -> None:
        msg = {"group_id": info["group_id"], "epoch": info["epoch"], "kind": kind, kind: data}
        if to is not None:
            msg["to"] = to
        self.directory.mls_put_handshake(msg)
        self.publish(WELCOME_TOPIC if kind == "welcome" else COMMIT_TOPIC, msg)

    def reconcile(self) -> None:
        with self._lock:
            g = self._group
        if g is None:
            info = self.mls.call("create_group", group_id=os.urandom(16).hex())
            self._install(info, "created the group")
            g = info
        members = {m["identity"]: m for m in g["members"]}
        desired = set(self.trusted_peers()) | {self.device_id}
        stale = [d for d in members if d not in desired]
        if stale:
            self._commit_remove(stale, reason="no longer trusted (revoked or unverified)")
        missing = sorted(d for d in desired if d not in members)
        if missing:
            self._add(missing)

    def _commit_remove(self, devices: list[str], reason: str) -> None:
        start = time.perf_counter()
        info = self.mls.call("remove", identities=devices)
        self.last_commit_ms = (time.perf_counter() - start) * 1000
        self._broadcast("commit", info, info["commit"])
        self._install(info, f"removed {', '.join(devices)}: {reason}")

    def _add(self, devices: list[str]) -> None:
        kps, ok = [], []
        for dev in devices:
            kp = self.directory.mls_get_key_package(dev)
            if kp is None or kp in self._used_kps:
                continue  # key packages are single-use: wait for a fresh one
            claim = self.mls.call("inspect_key_package", key_package=kp)
            pub = self.certified_key(dev)
            if claim["identity"] != dev or pub is None:
                self.log.info(f"not adding {dev}: key package identity/certificate not verified")
                continue
            if claim["signature_key"] != raw_public(pub).hex():
                reason = (
                    f"key package for '{dev}' is signed by a key that is NOT its certified "
                    "key — directory key substitution?"
                )
                self.log.info(f"✗ {reason}")
                self.on_alert("critical", f"Key substitution caught for {dev}", reason)
                continue
            kps.append(kp)
            ok.append(dev)
        if not kps:
            return
        start = time.perf_counter()
        info = self.mls.call("add", key_packages=kps)
        self.last_commit_ms = (time.perf_counter() - start) * 1000
        self._used_kps.update(kps)
        now = time.monotonic()
        for dev in ok:
            self._added_at[dev] = now
        self._broadcast("commit", info, info["commit"])
        self._broadcast("welcome", info, info["welcome"], to=ok)
        self._install(info, f"added {', '.join(ok)}")
