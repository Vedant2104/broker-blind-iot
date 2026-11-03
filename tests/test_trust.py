"""Directory + transparency log + peer verification, wired in-process.

The negative cases model a compromised directory or log."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from directory.service import DirectoryStore
from directory.service import create_app as directory_app
from rootca import approvals
from rootca.root import PkiPaths, init_pki, issue_device_cert, load_admin_key, load_roster
from securelib.identity import DeviceKeys, read_private
from securelib.pki import TrustError
from securelib.services import DirectoryClient, LogClient
from securelib.trust import (
    KeyChanged,
    LogVerifier,
    PeerVerifier,
    PinStore,
    TreeHeadState,
    TrustAnchors,
)
from translog.service import LogStore
from translog.service import create_app as log_app


class Home:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.pki = PkiPaths(tmp / "offline", tmp / "public", tmp / "translog" / "log.key")
        init_pki(self.pki)
        self.root_pem = self.pki.root_crt.read_bytes()
        self.log_http = self.make_log("log")
        self.dir_store = DirectoryStore(tmp / "dir" / "store.json")
        self.dir_http = TestClient(
            directory_app(self.dir_store, self.root_pem, load_roster(self.pki), self.submit)
        )
        self.anchors = TrustAnchors(self.pki.public)

    def make_log(self, name: str, key=None) -> TestClient:
        key = key or read_private(self.pki.translog_key)
        store = LogStore(self.tmp / name / "leaves.txt", key)
        return TestClient(log_app(store, self.root_pem))

    def submit(self, der: bytes) -> dict:
        return LogClient(self.log_http).add(der)

    def keys(self, device_id: str, tag: str = "") -> DeviceKeys:
        keys, _ = DeviceKeys.load_or_create(self.tmp / "dev" / (device_id + tag), device_id)
        return keys

    def issue(self, keys: DeviceKeys) -> str:
        action = approvals.new_action("add-device", keys.device_id, keys.csr_pem)
        sigs = {a: approvals.sign_approval(load_admin_key(self.pki, a), action) for a in ("A", "B")}
        pem, _ = issue_device_cert(self.pki, action, keys.csr_pem, sigs)
        return pem.decode()

    def verifier(self, name: str = "v", log_http: TestClient | None = None) -> PeerVerifier:
        state = self.tmp / "state" / name
        log = LogVerifier(
            self.anchors, LogClient(log_http or self.log_http), TreeHeadState(state / "sth.json")
        )
        return PeerVerifier(
            self.anchors, DirectoryClient(self.dir_http), log, PinStore(state / "pins.json")
        )


@pytest.fixture
def home(tmp_path: Path) -> Home:
    return Home(tmp_path)


def test_published_cert_verifies_and_is_pinned(home: Home) -> None:
    keys = home.keys("front-door")
    out = DirectoryClient(home.dir_http).publish(home.issue(keys))
    assert out["leaf_index"] == 0
    v = home.verifier()
    first = v.verify("front-door")
    assert first.identity.fingerprint == keys.fingerprint
    assert first.pin == "pinned (first sight)"
    assert v.verify("front-door").pin == "matches pin"


def test_directory_rejects_cert_not_from_root(home: Home, tmp_path: Path) -> None:
    evil = PkiPaths(tmp_path / "e-off", tmp_path / "e-pub", tmp_path / "e-log")
    init_pki(evil)
    keys = home.keys("front-door")
    action = approvals.new_action("add-device", "front-door", keys.csr_pem)
    sigs = {a: approvals.sign_approval(load_admin_key(evil, a), action) for a in ("A", "B")}
    forged, _ = issue_device_cert(evil, action, keys.csr_pem, sigs)
    r = home.dir_http.post("/certs", json={"cert_pem": forged.decode()})
    assert r.status_code == 422
    r = home.log_http.post("/entries", json={"leaf": "00ff"})
    assert r.status_code == 422


def test_cert_served_but_not_logged_is_rejected(home: Home) -> None:
    """Compromised directory serves a valid cert that was never logged (split view)."""
    keys = home.keys("front-door")
    home.dir_store.update(
        lambda d: d["certs"].update(
            {
                "front-door": {
                    "device_id": "front-door",
                    "cert_pem": home.issue(keys),
                    "leaf_index": 0,
                    "fingerprint": keys.fingerprint,
                }
            }
        )
    )
    DirectoryClient(home.dir_http).publish(home.issue(home.keys("back-door")))  # log not empty
    with pytest.raises(TrustError, match="NOT in the transparency log"):
        home.verifier().verify("front-door")


def test_other_devices_cert_substituted_is_rejected(home: Home) -> None:
    """Directory answers a query for front-door with back-door's (valid) cert."""
    d = DirectoryClient(home.dir_http)
    d.publish(home.issue(home.keys("back-door")))
    entry = d.get_cert("back-door")
    with pytest.raises(TrustError, match="expected 'front-door'"):
        home.verifier().verify("front-door", entry=entry)


def test_rekeyed_device_trips_the_pin(home: Home) -> None:
    """Even a properly issued + logged new cert triggers the key-change alert."""
    d = DirectoryClient(home.dir_http)
    d.publish(home.issue(home.keys("thermostat")))
    v = home.verifier()
    v.verify("thermostat")
    d.publish(home.issue(home.keys("thermostat", tag="-new")))
    with pytest.raises(KeyChanged, match="KEY CHANGED for thermostat"):
        v.verify("thermostat")


def test_forked_log_detected(home: Home) -> None:
    """A log (holding the real log key) shows this verifier one history, then
    swaps to a different history of the same size: the consistency check fails."""
    front = home.anchors.verify_cert_pem(home.issue(home.keys("front-door"))).der
    back = home.anchors.verify_cert_pem(home.issue(home.keys("back-door"))).der
    back2 = home.anchors.verify_cert_pem(home.issue(home.keys("back-door", tag="-2"))).der

    real, fork = home.make_log("real"), home.make_log("fork")
    for leaf in (front, back):
        LogClient(real).add(leaf)
    for leaf in (front, back2):
        LogClient(fork).add(leaf)

    v = home.verifier("fork-test", log_http=real)
    v.log.fresh_sth()  # remembers the real log at size 2
    v.log.log = LogClient(fork)
    with pytest.raises(TrustError, match="not consistent"):
        v.log.fresh_sth()


def test_shrinking_log_detected(home: Home) -> None:
    d = DirectoryClient(home.dir_http)
    d.publish(home.issue(home.keys("front-door")))
    d.publish(home.issue(home.keys("back-door")))
    v = home.verifier()
    v.verify("front-door")
    v.log.log = LogClient(home.make_log("empty"))
    with pytest.raises(TrustError, match="shrank"):
        v.log.fresh_sth()


def test_sth_from_unauthorised_key_rejected(home: Home) -> None:
    imposter_log = home.make_log("imposter", key=Ed25519PrivateKey.generate())
    with pytest.raises(TrustError, match="not signed by the log"):
        home.verifier("x", log_http=imposter_log).log.fresh_sth()


def test_action_board_verifies_approvals(home: Home) -> None:
    keys = home.keys("garage-lock")
    action = approvals.new_action("add-device", "garage-lock", keys.csr_pem)
    d = DirectoryClient(home.dir_http)
    posted = d.post_action(action, keys.csr_pem.decode())
    aid = posted["id"]
    assert aid == approvals.action_id(action) and posted["status"] == "pending"

    good = approvals.sign_approval(load_admin_key(home.pki, "A"), action)
    assert d.approve(aid, "A", good)["approvals"] == {"A": good}
    r = home.dir_http.post(f"/actions/{aid}/approvals", json={"admin": "B", "signature": good})
    assert r.status_code == 422  # A's signature under B's name


def test_action_with_mismatched_csr_rejected(home: Home) -> None:
    keys = home.keys("garage-lock")
    action = approvals.new_action("add-device", "garage-lock", keys.csr_pem)
    r = home.dir_http.post("/actions", json={"action": action, "csr_pem": "other"})
    assert r.status_code == 422


def test_log_dedupes_and_persists(home: Home, tmp_path: Path) -> None:
    pem = home.issue(home.keys("front-door"))
    der = home.anchors.verify_cert_pem(pem).der
    first = LogClient(home.log_http).add(der)
    again = LogClient(home.log_http).add(der)
    assert first["index"] == again["index"] == 0
    reopened = LogStore(tmp_path / "log" / "leaves.txt", read_private(home.pki.translog_key))
    assert len(reopened.hashes) == 1


def test_revoked_peer_rejected_and_forged_revocation_ignored(home: Home) -> None:
    from rootca.root import issue_revocation
    from securelib.trust import Revoked

    d = DirectoryClient(home.dir_http)
    d.publish(home.issue(home.keys("thermostat")))
    v = home.verifier()
    v.verify("thermostat")

    action = approvals.new_action("remove-device", "thermostat")
    sigs = {a: approvals.sign_approval(load_admin_key(home.pki, a), action) for a in ("B", "C")}
    serial = d.get_cert("thermostat")["cert_pem"]
    serial_hex = format(home.anchors.verify_cert_pem(serial).serial, "x")
    signed, _ = issue_revocation(home.pki, action, sigs, serial_hex)

    # A revocation signed by someone else is refused by the directory and ignored by clients.
    fake = {**signed, "signature": "00" * 64}
    assert home.dir_http.post("/revocations", json={"signed": fake}).status_code == 422
    assert home.anchors.revoked([fake]) == {}

    d.publish_revocation(signed)
    with pytest.raises(Revoked, match="REVOKED"):
        v.verify("thermostat")
