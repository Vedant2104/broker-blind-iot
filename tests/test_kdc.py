"""Centralized group keys end to end over an in-memory broker:
join → rekey → revoke → the revoked device cannot read new traffic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kdc.service import Kdc
from securelib.channel import Channel
from securelib.groupkeys import CentralizedGroupKeys
from securelib.pki import TrustError


class Bus:
    """Synchronous in-memory pub/sub standing in for the broker."""

    def __init__(self) -> None:
        self.subs: dict[str, list] = {}
        self.retained: dict[str, bytes] = {}
        self.seen: list[str] = []

    def subscribe(self, topic: str, fn) -> None:
        self.subs.setdefault(topic, []).append(fn)
        if topic in self.retained:
            fn(topic, self.retained[topic])

    def publish(self, topic: str, payload: bytes, retain: bool = False) -> None:
        self.seen.append(topic)
        if retain:
            self.retained[topic] = payload
        for t, fns in list(self.subs.items()):
            if t == topic or (t.endswith("/+") and topic.rsplit("/", 1)[0] == t[:-2]):
                for fn in list(fns):
                    fn(topic, payload)


@dataclass
class FakeIdentity:
    ed25519: object
    serial: int = 1


@dataclass
class FakePeer:
    identity: FakeIdentity
    leaf_index: int = 0


class FakeVerifier:
    """Stands in for root/log/pin checks (covered in test_trust.py)."""

    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        self.keys = keys
        self.revoked: set[str] = set()

    def verify(self, dev: str, *_a):
        if dev not in self.keys:
            raise TrustError(f"directory has no certificate for {dev}")
        if dev in self.revoked:
            raise TrustError(f"{dev} is REVOKED")
        return FakePeer(FakeIdentity(self.keys[dev].public_key()))

    def revocations(self) -> dict[str, set[int]]:
        return {d: {1} for d in self.revoked}


class Home:
    def __init__(self, tmp: Path, names=("phone", "front-door", "thermostat")) -> None:
        self.bus = Bus()
        self.kdc_key = Ed25519PrivateKey.generate()
        self.dev_keys = {n: Ed25519PrivateKey.generate() for n in names}
        self.verifier = FakeVerifier(self.dev_keys)
        self.kdc = Kdc(self.kdc_key, self.verifier, self._kdc_publish, tmp / "epoch")
        self.bus.subscribe("kdc/join/+", self.kdc.on_message)
        self.alerts: list[str] = []
        self.groups = {n: self._device(n) for n in names}

    def _kdc_publish(self, topic: str, msg: dict, retain: bool = False) -> None:
        self.bus.publish(topic, json.dumps(msg).encode(), retain)

    def _device(self, name: str) -> CentralizedGroupKeys:
        g = CentralizedGroupKeys(
            name,
            self.dev_keys[name],
            kdc_key=lambda: self.kdc_key.public_key(),
            publish=lambda t, m: self.bus.publish(t, json.dumps(m).encode()),
            may_join=lambda: True,
            on_alert=lambda sev, title, reason: self.alerts.append(reason),
        )
        for t in g.subscriptions():
            self.bus.subscribe(t, g.handle)
        return g

    def settle(self) -> None:
        if self.kdc._rekey_at is not None:
            self.kdc.rekey("test")

    def channel(self, name: str) -> Channel:
        return Channel(
            name,
            "on",
            group=self.groups[name],
            signer=self.dev_keys[name],
            peer_key=lambda s: self.dev_keys[s].public_key() if s in self.dev_keys else None,
            requires_signature=lambda t: t.endswith("/cmd"),
        )


@pytest.fixture
def home(tmp_path: Path) -> Home:
    h = Home(tmp_path)
    h.kdc.announce()  # devices join on the (retained) announcement
    h.settle()
    return h


def test_all_members_share_one_epoch_key(home: Home) -> None:
    epochs = {g.current()[0] for g in home.groups.values()}
    keys = {g.current()[1] for g in home.groups.values()}
    assert len(epochs) == 1 and len(keys) == 1
    assert home.kdc.status()["members"] == ["front-door", "phone", "thermostat"]
    assert "key" not in json.dumps(home.kdc.status()).replace("keys", "")  # never exposes keys


def test_sealed_message_between_members(home: Home) -> None:
    payload = home.channel("phone").seal("home/door/front/cmd", {"cmd": "unlock"})
    opened = home.channel("front-door").open("home/door/front/cmd", payload)
    assert opened.ok and opened.body == {"cmd": "unlock"} and opened.signed


def test_new_member_triggers_rekey(home: Home, tmp_path: Path) -> None:
    before = home.groups["phone"].current()[0]
    home.dev_keys["garage-lock"] = Ed25519PrivateKey.generate()
    home.groups["garage-lock"] = home._device("garage-lock")
    home.groups["garage-lock"].start_join()
    assert home.groups["garage-lock"].current() is None  # no old key for newcomers
    home.settle()
    assert home.groups["phone"].current()[0] == before + 1
    assert home.groups["garage-lock"].current() == home.groups["phone"].current()


def test_rejoin_gets_current_key_without_rekey(home: Home) -> None:
    epoch = home.kdc.epoch
    home.groups["phone"].rejoin()
    assert home.kdc._rekey_at is None and home.kdc.epoch == epoch


def test_revoked_device_cannot_read_new_traffic(home: Home) -> None:
    old_epoch = home.groups["thermostat"].current()[0]
    home.verifier.revoked.add("thermostat")
    home.kdc.check_revocations()
    assert "thermostat" not in home.kdc.status()["members"]
    assert home.groups["phone"].current()[0] == old_epoch + 1
    assert home.groups["thermostat"].current()[0] == old_epoch  # stuck on the old key

    payload = home.channel("phone").seal("home/door/front/cmd", {"cmd": "unlock"})
    opened = home.channel("thermostat").open("home/door/front/cmd", payload)
    assert not opened.ok and opened.reason.startswith("wrong epoch")

    # ...and it cannot get back in.
    home.groups["thermostat"].rejoin()
    assert home.groups["thermostat"].current()[0] == old_epoch


def test_unknown_device_cannot_join(home: Home) -> None:
    stranger = Ed25519PrivateKey.generate()
    g = CentralizedGroupKeys(
        "intruder",
        stranger,
        kdc_key=lambda: home.kdc_key.public_key(),
        publish=lambda t, m: home.bus.publish(t, json.dumps(m).encode()),
        may_join=lambda: True,
        on_alert=lambda *a: None,
    )
    for t in g.subscriptions():
        home.bus.subscribe(t, g.handle)
    g.start_join()
    assert g.current() is None and "intruder" not in home.kdc.status()["members"]


def test_unsigned_join_refused_unless_allowed(home: Home) -> None:
    g = home.groups["thermostat"]
    epoch = home.kdc.epoch
    g._epoch = g._key = None  # forget the key, then try an unsigned join
    g.rejoin("unsigned")
    assert g.current() is None
    home.kdc.allow_unsigned.add("thermostat")
    g.rejoin("unsigned")
    assert g.current()[0] == epoch
    assert "thermostat" not in home.kdc.allow_unsigned  # one-shot


def test_epoch_survives_kdc_restart(home: Home, tmp_path: Path) -> None:
    epoch = home.kdc.epoch
    again = Kdc(home.kdc_key, home.verifier, home._kdc_publish, tmp_path / "epoch")
    assert again.epoch == epoch + 1


def test_old_key_message_ignored(home: Home) -> None:
    g = home.groups["phone"]
    epoch, key = g.current()
    from securelib.kdcproto import wrap_key

    stale = wrap_key(g._kek, "phone", epoch - 1, b"\x00" * 32)
    home.bus.publish("kdc/key/phone", json.dumps(stale).encode())
    assert g.current() == (epoch, key)


def test_sequence_numbers_survive_restart(tmp_path: Path) -> None:
    from securelib.channel import SeqCounter

    a = SeqCounter(tmp_path / "seq")
    first = [a.next() for _ in range(5)]
    b = SeqCounter(tmp_path / "seq")
    assert b.next() > max(first)


def test_repaired_device_with_new_cert_can_rejoin(home: Home) -> None:
    """Revocation is per certificate: a re-commissioned device (new serial) may rejoin,
    and the old-serial revocation does not evict it again."""
    home.verifier.revoked.add("thermostat")
    home.kdc.check_revocations()
    assert "thermostat" not in home.kdc.status()["members"]

    key = home.dev_keys["thermostat"].public_key()
    home.verifier.verify = lambda dev, *_a: FakePeer(
        FakeIdentity(home.dev_keys[dev].public_key(), serial=2 if dev == "thermostat" else 1)
    )
    home.verifier.revocations = lambda: {"thermostat": {1}}  # only the OLD serial is revoked
    home.groups["thermostat"].rejoin()
    home.settle()
    assert "thermostat" in home.kdc.status()["members"]
    home.kdc.check_revocations()
    assert "thermostat" in home.kdc.status()["members"]
    assert key is not None
