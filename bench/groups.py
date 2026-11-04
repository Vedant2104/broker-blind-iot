"""Join / revoke / rekey cost vs group size, centralized (KDC) vs decentralized (MLS).

Simulated members, real code:
- centralized: the real `Kdc.rekey()` (fresh key, AES-GCM-wrapped to each member's
  pairwise key) with N members; a join also runs the signed X25519 handshake.
  Certificate checks (directory / log lookups) are left out: they are network
  round trips, the same in both modes.
- decentralized: real OpenMLS commits from the bbiot-mls sidecar. The admin commits;
  one real member processes each commit (that is when it has the new key).

Messages/bytes are what our implementation publishes: KDC key messages are JSON with
hex, MLS commits/welcomes are JSON with hex (as securelib.mls broadcasts them).
"""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bench.common import Emit, mqtt_publish_size, results_dir, write_csv
from securelib.groupkeys import key_topic
from securelib.kdcproto import DeviceJoin, KdcJoin, unwrap_key
from securelib.mls import COMMIT_TOPIC, WELCOME_TOPIC, MlsError, MlsSidecar, find_binary
from securelib.pki import raw_public


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


# --- centralized ----------------------------------------------------------------------------------


def _kdc(size: int, tmp: Path):
    from kdc.service import Kdc

    sent: list[tuple[str, bytes]] = []

    def publish(topic: str, msg: dict, retain: bool = False) -> None:
        sent.append((topic, json.dumps(msg, separators=(",", ":")).encode()))

    kdc = Kdc(Ed25519PrivateKey.generate(), verifier=None, publish=publish, epoch_file=tmp / "e")
    kdc.members = {f"dev-{i:04d}": os.urandom(32) for i in range(size)}
    return kdc, sent


def _wire(sent: list[tuple[str, bytes]]) -> int:
    return sum(mqtt_publish_size(t, len(p)) for t, p in sent)


def centralized(size: int, reps: int) -> list[dict]:
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        kdc, sent = _kdc(size, Path(tmp))
        kdc_key = Ed25519PrivateKey.generate()
        dev_key = Ed25519PrivateKey.generate()
        member, member_kek = "dev-0000", kdc.members["dev-0000"]

        def member_unwrap() -> float:
            topic, payload = next((t, p) for t, p in sent if t == key_topic(member))
            t0 = time.perf_counter()
            unwrap_key(member_kek, member, json.loads(payload))
            return _ms(t0)

        for op in ("rekey", "join", "revoke"):
            times, member_times, msgs, wire = [], [], [], []
            for r in range(reps):
                sent.clear()
                t0 = time.perf_counter()
                if op == "join":  # signed handshake with the newcomer, then rekey to all
                    dev = DeviceJoin(f"new-{r}")
                    k = KdcJoin.from_hello(dev.hello())
                    challenge = k.challenge(kdc_key)
                    finish, _ = dev.on_challenge(challenge, kdc_key.public_key(), dev_key)
                    kdc.members[f"new-{r}"] = k.on_finish(finish, dev_key.public_key())
                    hs = [
                        ("kdc/join/new", dev.hello()),
                        ("kdc/session/new", challenge),
                        ("kdc/join/new", finish),
                    ]
                    sent.extend((t, json.dumps(m).encode()) for t, m in hs)
                    kdc.rekey("bench join")
                elif op == "revoke":
                    kdc.members.pop(f"dev-{size - 1 - r:04d}", None)
                    kdc.rekey("bench revoke")
                else:
                    kdc.rekey("bench rekey")
                times.append(_ms(t0))
                member_times.append(member_unwrap())
                msgs.append(len(sent))
                wire.append(_wire(sent))
                if op == "join":
                    kdc.members.pop(f"new-{r}")
                if op == "revoke":
                    kdc.members[f"dev-{size - 1 - r:04d}"] = os.urandom(32)
            rows.append(_row("centralized", size, op, times, member_times, msgs, wire))
    return rows


# --- decentralized ---------------------------------------------------------------------------


def _sidecar(name: str) -> tuple[MlsSidecar, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    s = MlsSidecar()
    s.call(
        "init",
        identity=name,
        sig_priv=key.private_bytes_raw().hex(),
        sig_pub=raw_public(key.public_key()).hex(),
    )
    return s, key


def _key_packages(factory: MlsSidecar, names: list[str]) -> list[str]:
    """One helper sidecar makes key packages for many simulated members."""
    kps = []
    for name in names:
        key = Ed25519PrivateKey.generate()
        factory.call(
            "init",
            identity=name,
            sig_priv=key.private_bytes_raw().hex(),
            sig_pub=raw_public(key.public_key()).hex(),
        )
        kps.append(factory.call("key_package")["key_package"])
    return kps


def _mls_msg(info: dict, kind: str, data: str, to: list[str] | None = None) -> tuple[str, bytes]:
    msg = {"group_id": info["group_id"], "epoch": info["epoch"], "kind": kind, kind: data}
    if to is not None:
        msg["to"] = to
    topic = WELCOME_TOPIC if kind == "welcome" else COMMIT_TOPIC
    return topic, json.dumps(msg, separators=(",", ":")).encode()


def decentralized(size: int, reps: int, emit: Emit) -> list[dict]:
    admin, _ = _sidecar("hub")
    observer, _ = _sidecar("observer")
    factory, _ = _sidecar("factory")
    try:
        admin.call("create_group", group_id=os.urandom(16).hex())
        others = [f"dev-{i:04d}" for i in range(size - 2)]
        t0 = time.perf_counter()
        info = admin.call(
            "add",
            key_packages=[
                observer.call("key_package")["key_package"],
                *_key_packages(factory, others),
            ],
        )
        observer.call("welcome", welcome=info["welcome"])
        emit(f"[bench]     MLS group of {size} set up in {_ms(t0) / 1000:.1f} s")

        rows = []
        for op in ("rekey", "join", "revoke"):
            times, member_times, msgs, wire = [], [], [], []
            for r in range(reps):
                sent = []
                if op == "join":
                    kp = _key_packages(factory, [f"new-{r}"])
                    t0 = time.perf_counter()
                    out = admin.call("add", key_packages=kp)
                    times.append(_ms(t0))
                    sent += [
                        _mls_msg(out, "commit", out["commit"]),
                        _mls_msg(out, "welcome", out["welcome"], [f"new-{r}"]),
                    ]
                elif op == "revoke":
                    t0 = time.perf_counter()
                    out = admin.call("remove", identities=[others[r]])
                    times.append(_ms(t0))
                    sent.append(_mls_msg(out, "commit", out["commit"]))
                else:
                    t0 = time.perf_counter()
                    out = admin.call("update")
                    times.append(_ms(t0))
                    sent.append(_mls_msg(out, "commit", out["commit"]))
                t0 = time.perf_counter()
                observer.call("commit", commit=out["commit"], expected_committer="hub")
                member_times.append(_ms(t0))
                msgs.append(len(sent))
                wire.append(_wire(sent))
                # keep the group at `size` for the next run (not timed)
                if op == "join":
                    back = admin.call("remove", identities=[f"new-{r}"])
                    observer.call("commit", commit=back["commit"])
                if op == "revoke":
                    back = admin.call("add", key_packages=_key_packages(factory, [f"re-{r}"]))
                    observer.call("commit", commit=back["commit"])
            rows.append(_row("decentralized", size, op, times, member_times, msgs, wire))
        return rows
    finally:
        for s in (admin, observer, factory):
            s.close()


def _row(mode: str, size: int, op: str, times, member_times, msgs, wire) -> dict:
    return {
        "mode": mode,
        "size": size,
        "op": op,
        "reps": len(times),
        "admin_ms": round(statistics.median(times), 3),
        "member_ms": round(statistics.median(member_times), 3),
        "messages": round(statistics.median(msgs)),
        "bytes": round(statistics.median(wire)),
    }


def run(emit: Emit, sizes: list[int], reps: int, out: Path | None = None) -> list[dict]:
    import logging

    import kdc.service  # noqa: F401 - create its logger first, then quiet it

    out = out or results_dir()
    rows: list[dict] = []
    kdc_log = logging.getLogger("kdc")
    level = kdc_log.level
    kdc_log.setLevel(logging.WARNING)  # its REKEY line lists every member
    try:
        rows = _run_sizes(emit, sizes, reps)
    finally:
        kdc_log.setLevel(level)
    write_csv(out / "groups.csv", rows)
    emit(f"[bench] → {(out / 'groups.csv').as_posix()}")
    return rows


def _run_sizes(emit: Emit, sizes: list[int], reps: int) -> list[dict]:
    rows: list[dict] = []
    mls_ok = find_binary() is not None
    for size in sizes:
        emit(f"[bench] group size {size}: centralized (KDC)")
        rows += centralized(size, reps)
        if mls_ok:
            emit(f"[bench] group size {size}: decentralized (MLS)")
            try:
                rows += decentralized(size, reps, emit)
            except MlsError as exc:
                emit(f"[bench]   ✗ MLS failed: {exc}")
        for r in rows[-6:]:
            if r["size"] == size:
                emit(
                    f"[bench]   {r['mode']:<13} {r['op']:<6} admin {r['admin_ms']:>8.2f} ms  "
                    f"member {r['member_ms']:>6.2f} ms  {r['messages']:>5} msgs  "
                    f"{r['bytes']:>8} B"
                )
    if not mls_ok:
        emit(
            "[bench] decentralized (MLS) skipped: bbiot-mls is not on this machine. Run inside "
            "the image: docker compose run --rm cli bench full"
        )
    return rows
