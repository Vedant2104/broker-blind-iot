"""Benchmarks: the helpers compute the right sizes, and each part runs and writes CSVs."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bench import charts, common, crypto, groups, messages


def test_mqtt_publish_size() -> None:
    # 1 type byte + 1 length byte + (2 + 5 topic + 2 packet id + 10 payload)
    assert common.mqtt_publish_size("a/b/c", 10) == 2 + 19
    assert common.mqtt_publish_size("a/b/c", 10, qos=0) == 2 + 17
    # remaining length >= 128 needs a 2-byte varint
    assert common.mqtt_publish_size("t", 200) == 1 + 2 + (2 + 1 + 2 + 200)


@pytest.mark.parametrize(
    ("version", "cipher", "expected"),
    [
        ("TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384", 29),
        ("TLSv1.2", "ECDHE-ECDSA-CHACHA20-POLY1305", 21),
        ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 22),
    ],
)
def test_tls_overhead(version: str, cipher: str, expected: int) -> None:
    assert common.tls_overhead(version, cipher) == expected


def test_summarize() -> None:
    s = common.summarize([1.0, 2.0, 3.0, 4.0, 100.0])
    assert s["median"] == 3.0 and s["p95"] == 100.0


def test_byte_rows_show_our_overhead() -> None:
    rows = messages.byte_rows(
        os.urandom(32), Ed25519PrivateKey.generate(), ("TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384")
    )
    by = {(r["kind"], r["mode"]): r for r in rows}
    for kind in ("state", "command"):
        plain, tls, ours = (by[(kind, m)] for m in ("plain", "tls", "ours"))
        assert plain["added_vs_plain"] == 0
        assert tls["added_vs_plain"] == 29  # same payload, plus one TLS record
        assert ours["added_vs_plain"] > tls["added_vs_plain"]
    # commands carry a 64-byte Ed25519 signature on top of the AEAD
    assert by[("command", "ours")]["payload_bytes"] > by[("state", "ours")]["payload_bytes"] + 40


def test_centralized_rekey_sends_one_key_per_member() -> None:
    rows = {r["op"]: r for r in groups.centralized(20, reps=2)}
    assert rows["rekey"]["messages"] == 20
    assert rows["revoke"]["messages"] == 19
    assert rows["join"]["messages"] == 21 + 3  # 3 handshake messages + key to 21 members
    assert rows["rekey"]["bytes"] > 0 and rows["rekey"]["admin_ms"] > 0


def test_crypto_writes_csv(tmp_path: Path) -> None:
    lines: list[str] = []
    rows = crypto.run(lines.append, n=30, out=tmp_path / "crypto-test.csv")
    ops = {r["op"] for r in rows}
    assert {
        "Ed25519 sign (64 B)",
        "seal command (AEAD + Ed25519)",
        "open state message (all checks)",
    } <= ops
    assert (tmp_path / "crypto-test.csv").is_file()


def test_charts_from_csvs(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    common.write_csv(
        tmp_path / "message_bytes.csv",
        messages.byte_rows(os.urandom(32), Ed25519PrivateKey.generate(), ("TLSv1.3", "x")),
    )
    common.write_csv(tmp_path / "groups.csv", groups.centralized(10, reps=1))
    written = charts.render(lambda _l: None, tmp_path)
    names = {p.name for p in written}
    assert {"message_bytes.png", "rekey_time.png", "rekey_bytes.png"} <= names
