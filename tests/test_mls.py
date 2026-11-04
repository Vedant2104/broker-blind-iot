"""Decentralized group keys with real OpenMLS (needs the bbiot-mls binary:
`make test-mls` runs these inside the bbiot image)."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from securelib.channel import Channel
from securelib.mls import DecentralizedGroupKeys, MlsError, MlsSidecar, find_binary
from securelib.pki import raw_public

pytestmark = [
    pytest.mark.mls,
    pytest.mark.skipif(find_binary() is None, reason="bbiot-mls binary not available"),
]


# --- raw sidecar ------------------------------------------------------------------------------


def sidecar(name: str, key: Ed25519PrivateKey) -> MlsSidecar:
    s = MlsSidecar()
    s.call(
        "init",
        identity=name,
        sig_priv=key.private_bytes_raw().hex(),
        sig_pub=raw_public(key.public_key()).hex(),
    )
    return s


def test_key_package_is_bound_to_the_device_key() -> None:
    key = Ed25519PrivateKey.generate()
    s = sidecar("thermostat", key)
    kp = s.call("key_package")["key_package"]
    claim = s.call("inspect_key_package", key_package=kp)
    assert claim == {"identity": "thermostat", "signature_key": raw_public(key.public_key()).hex()}


def test_tampered_key_package_rejected() -> None:
    s = sidecar("thermostat", Ed25519PrivateKey.generate())
    kp = bytearray.fromhex(s.call("key_package")["key_package"])
    kp[-10] ^= 0x01
    with pytest.raises(MlsError, match="invalid"):
        s.call("inspect_key_package", key_package=kp.hex())


def test_group_lifecycle_with_openmls() -> None:
    keys = {n: Ed25519PrivateKey.generate() for n in ("phone", "front-door", "thermostat", "smoke")}
    sides = {n: sidecar(n, k) for n, k in keys.items()}
    admin = sides["phone"]
    admin.call("create_group", group_id="aa" * 16)
    kps = [
        sides[n].call("key_package")["key_package"] for n in ("front-door", "thermostat", "smoke")
    ]
    added = admin.call("add", key_packages=kps)
    assert added["epoch"] == 1 and len(added["members"]) == 4
    for n in ("front-door", "thermostat", "smoke"):
        assert sides[n].call("welcome", welcome=added["welcome"])["epoch"] == 1

    secrets = {n: s.call("export", label="t", length=32)["secret"] for n, s in sides.items()}
    assert len(set(secrets.values())) == 1  # everyone derived the same group key

    removed = admin.call("remove", identities=["thermostat"])
    for n in ("front-door", "smoke"):
        out = sides[n].call("commit", commit=removed["commit"], expected_committer="phone")
        assert out["epoch"] == 2 and out["committer"] == "phone"
    gone = sides["thermostat"].call("commit", commit=removed["commit"])
    assert gone == {"removed": True, "committer": "phone"}
    with pytest.raises(MlsError):
        sides["thermostat"].call("export", label="t", length=32)  # no key for epoch 2

    new = {n: sides[n].call("export", label="t", length=32)["secret"] for n in ("phone", "smoke")}
    assert len(set(new.values())) == 1 and secrets["phone"] not in new.values()


def test_commit_from_non_admin_refused() -> None:
    keys = {n: Ed25519PrivateKey.generate() for n in ("phone", "front-door", "thermostat")}
    sides = {n: sidecar(n, k) for n, k in keys.items()}
    sides["phone"].call("create_group", group_id="bb" * 16)
    kps = [sides[n].call("key_package")["key_package"] for n in ("front-door", "thermostat")]
    added = sides["phone"].call("add", key_packages=kps)
    for n in ("front-door", "thermostat"):
        sides[n].call("welcome", welcome=added["welcome"])
    # A compromised thermostat tries to kick the front door out.
    rogue = sides["thermostat"].call("remove", identities=["front-door"])
    with pytest.raises(MlsError, match="refused"):
        sides["front-door"].call("commit", commit=rogue["commit"], expected_committer="phone")
    assert sides["front-door"].call("status")["epoch"] == 1


# --- DecentralizedGroupKeys over an in-memory broker + directory ------------------------------


class Bus:
    def __init__(self) -> None:
        self.subs: dict[str, list] = {}
        self.drop: set[str] = set()

    def subscribe(self, topic: str, fn) -> None:
        self.subs.setdefault(topic, []).append(fn)

    def publish(self, topic: str, msg: dict) -> None:
        if topic in self.drop:
            return
        payload = json.dumps(msg).encode()
        for t, fns in list(self.subs.items()):
            if t == topic or (t.endswith("/+") and topic.rsplit("/", 1)[0] == t[:-2]):
                for fn in list(fns):
                    fn(topic, payload)


class FakeDirectory:
    def __init__(self) -> None:
        self.kps: dict[str, str] = {}
        self.handshakes: list[dict] = []
        self.forged: dict[str, str] = {}

    def mls_put_key_package(self, dev: str, kp: str) -> None:
        self.kps[dev] = kp

    def mls_get_key_package(self, dev: str) -> str | None:
        return self.forged.get(dev) or self.kps.get(dev)

    def mls_put_handshake(self, msg: dict) -> None:
        self.handshakes.append(msg)

    def mls_handshakes(self, group_id: str, after: int = -1) -> list[dict]:
        return sorted(
            (h for h in self.handshakes if h["group_id"] == group_id and h["epoch"] > after),
            key=lambda h: h["epoch"],
        )


class Home:
    NAMES = ("phone", "front-door", "thermostat")

    def __init__(self) -> None:
        self.bus, self.dir = Bus(), FakeDirectory()
        self.keys = {n: Ed25519PrivateKey.generate() for n in self.NAMES}
        self.trusted = set(self.NAMES)
        self.alerts: list[str] = []
        self.g = {n: self._make(n) for n in self.NAMES}

    def _make(self, name: str) -> DecentralizedGroupKeys:
        g = DecentralizedGroupKeys(
            name,
            self.keys[name],
            "phone",
            publish=self.bus.publish,
            certified_key=lambda d: self.keys[d].public_key() if d in self.keys else None,
            directory=self.dir,
            on_alert=lambda sev, title, reason: self.alerts.append(reason),
            trusted_peers=lambda: sorted(self.trusted - {name}),
        )
        for t in g.subscriptions():
            self.bus.subscribe(t, g.handle)
        return g

    def run(self, rounds: int = 2) -> None:
        for _ in range(rounds):
            for n in self.NAMES:
                if n != "phone":
                    self.g[n].tick()  # publish key packages
            self.g["phone"].tick()  # admin reconciles

    def channel(self, name: str) -> Channel:
        return Channel(
            name,
            "on",
            group=self.g[name],
            signer=self.keys[name],
            peer_key=lambda s: self.keys[s].public_key(),
            requires_signature=lambda t: t.endswith("/cmd"),
        )


@pytest.fixture
def home() -> Home:
    h = Home()
    h.run()
    return h


def test_members_share_a_key_and_messages_flow(home: Home) -> None:
    keys = {n: home.g[n].current() for n in home.NAMES}
    assert len({k for k in keys.values()}) == 1 and None not in keys.values()
    sealed = home.channel("phone").seal("home/door/front/cmd", {"cmd": "unlock"})
    opened = home.channel("front-door").open("home/door/front/cmd", sealed)
    assert opened.ok and opened.body == {"cmd": "unlock"}


def test_untrusted_device_is_removed_and_cannot_read(home: Home) -> None:
    old = home.g["thermostat"].current()
    home.trusted.discard("thermostat")  # e.g. its certificate was revoked
    home.run(1)
    assert home.g["phone"].current()[0] == old[0] + 1
    assert "thermostat" not in home.g["phone"].status()["members"]
    assert home.g["thermostat"].current() is None
    sealed = home.channel("phone").seal("home/door/front/cmd", {"cmd": "unlock"})
    assert not home.channel("thermostat").open("home/door/front/cmd", sealed).ok


def test_substituted_key_package_is_caught() -> None:
    """Attack 9 (decentralized): the directory serves the attacker's key package."""
    h = Home()
    attacker = sidecar("thermostat", Ed25519PrivateKey.generate())
    h.dir.forged["thermostat"] = attacker.call("key_package")["key_package"]
    h.run()
    assert "thermostat" not in h.g["phone"].status()["members"]
    assert any("NOT its certified key" in a for a in h.alerts)
    assert h.g["front-door"].current() == h.g["phone"].current()  # others unaffected


def test_missed_commit_is_fetched_from_the_directory(home: Home) -> None:
    home.bus.drop.add("mls/commit")  # broker drops the commit
    home.trusted.discard("thermostat")
    home.run(1)
    home.bus.drop.clear()
    assert home.g["front-door"].current() != home.g["phone"].current()
    home.g["front-door"].catch_up()
    assert home.g["front-door"].current() == home.g["phone"].current()


def test_forged_rejoin_request_ignored(home: Home) -> None:
    epoch = home.g["phone"].current()[0]
    home.bus.publish("mls/rejoin/front-door", {"ts": 0, "sig": "00" * 64})
    assert home.g["phone"].current()[0] == epoch


@pytest.mark.parametrize("processed_removal", [True, False])
def test_removed_member_can_be_readded_to_the_same_group(processed_removal: bool) -> None:
    """Regression: stale group state made re-joining the same group fail
    (GroupAlreadyExists), which also burned the member's key package."""
    a = sidecar("phone", Ed25519PrivateKey.generate())
    b = sidecar("thermostat", Ed25519PrivateKey.generate())
    a.call("create_group", group_id="cc" * 16)
    added = a.call("add", key_packages=[b.call("key_package")["key_package"]])
    b.call("welcome", welcome=added["welcome"])
    fresh = b.call("key_package")["key_package"]
    removed = a.call("remove", identities=["thermostat"])
    if processed_removal:
        assert b.call("commit", commit=removed["commit"])["removed"] is True
    readded = a.call("add", key_packages=[fresh])
    assert b.call("welcome", welcome=readded["welcome"])["epoch"] == readded["epoch"]
    assert b.call("export", label="t", length=32) == a.call("export", label="t", length=32)


def test_epoch_refused_until_member_verifies_then_accepted(home: Home) -> None:
    """A member whose certificate this device hasn't verified yet makes it refuse
    the epoch — and accept it once the certificate checks out."""
    home.keys["garage-lock"] = Ed25519PrivateKey.generate()
    pending = set()
    real_certified = home.g["front-door"].certified_key
    home.g["front-door"].certified_key = lambda d: None if d in pending else real_certified(d)
    pending.add("garage-lock")
    home.g["garage-lock"] = home._make("garage-lock")
    home.trusted.add("garage-lock")
    Home.NAMES = (*Home.NAMES, "garage-lock")
    try:
        home.run()
        assert home.g["front-door"].current() != home.g["phone"].current()  # refused
        pending.clear()  # front-door's trust watch catches up
        home.g["front-door"].tick()
        assert home.g["front-door"].current() == home.g["phone"].current()
    finally:
        Home.NAMES = ("phone", "front-door", "thermostat")


def test_member_removed_while_offline_accepts_readd(home: Home) -> None:
    """Regression: a device that missed its own removal (it was disconnected, e.g.
    quarantined) must still accept the welcome that re-adds it."""
    home.bus.drop.add("mls/commit")  # it never hears about its removal
    home.trusted.discard("thermostat")
    home.run(1)
    home.bus.drop.clear()
    assert home.g["thermostat"].current() is not None  # still thinks it's in
    home.g["thermostat"].publish_key_package()  # fresh key package for the re-add
    home.trusted.add("thermostat")
    home.run(1)
    assert home.g["thermostat"].current() == home.g["phone"].current()


def test_rejoin_request_comes_with_a_fresh_key_package(home: Home) -> None:
    """Regression: if the admin spent a member's key package on a welcome the member
    never got, the member's rejoin request must offer a new one."""
    home.bus.drop.update({"mls/welcome", "mls/commit"})
    g = home.g["thermostat"]
    g._group = g._key = None  # it lost its state
    g.request_rejoin(force=True)  # admin re-adds it; the welcome is dropped
    home.bus.drop.clear()
    assert g.current() is None
    home.g["phone"]._added_at.clear()  # (skip the admin's 8-second grace in this test)
    g.request_rejoin(force=True)  # asks again — with a fresh key package this time
    assert g.current() == home.g["phone"].current()


def test_benchmark_decentralized_ops() -> None:
    """bench/groups.py drives real OpenMLS commits: one commit per op, a welcome on join."""
    from bench import groups

    rows = {r["op"]: r for r in groups.decentralized(6, reps=1, emit=lambda _l: None)}
    assert set(rows) == {"join", "revoke", "rekey"}
    assert rows["rekey"]["messages"] == 1 and rows["revoke"]["messages"] == 1
    assert rows["join"]["messages"] == 2  # commit + welcome
    assert all(r["bytes"] > 0 and r["member_ms"] > 0 for r in rows.values())
