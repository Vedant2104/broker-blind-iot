"""Shared helpers for the benchmarks: where results go, CSV I/O, stats, sizes."""

from __future__ import annotations

import contextlib
import csv
import os
import platform
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cryptography

Emit = Callable[[str], None]

# Per-message byte overhead of one TLS record carrying one MQTT packet (all fixed sizes):
# TLS 1.2 AES-GCM: 5 header + 8 explicit nonce + 16 tag; ChaCha20: 5 + 16;
# TLS 1.3 (any AEAD): 5 header + 1 inner content type + 16 tag.
TLS_RECORD_OVERHEAD = {
    ("TLSv1.2", "GCM"): 29,
    ("TLSv1.2", "CHACHA20"): 21,
    ("TLSv1.3", "*"): 22,
}


def results_dir(quick: bool = False) -> Path:
    base = Path(os.environ.get("BBIOT_BENCH_DIR", "bench/results"))
    path = base / "quick" if quick else base
    path.mkdir(parents=True, exist_ok=True)
    return path


def host_info() -> dict[str, str]:
    """What machine the numbers came from (crypto timings differ per CPU)."""
    machine = platform.machine() or "?"
    model = ""
    with contextlib.suppress(OSError):  # Raspberry Pi and other ARM boards name themselves
        model = Path("/proc/device-tree/model").read_text("utf-8").strip("\x00\n ")
    label = os.environ.get("BBIOT_BENCH_HOST_LABEL")
    return {
        "host": label or model or f"{platform.system()} {machine}",
        "machine": machine,
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> Path:
    if not rows:
        return path
    fields: list[str] = []
    for row in rows:
        fields += [k for k in row if k not in fields]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarize(samples: list[float]) -> dict[str, float]:
    """Median / p95 / mean of a list of samples (same unit in, same unit out)."""
    s = sorted(samples)
    p95 = s[min(len(s) - 1, round(0.95 * (len(s) - 1)))]
    return {
        "median": round(statistics.median(s), 4),
        "p95": round(p95, 4),
        "mean": round(statistics.fmean(s), 4),
    }


def time_us(fn: Callable[[], Any], n: int, warmup: int = 20) -> list[float]:
    """Run ``fn`` n times; return each run's duration in microseconds."""
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t) / 1000)
    return out


def _varint_len(n: int) -> int:
    size = 1
    while n >= 128:
        n //= 128
        size += 1
    return size


def mqtt_publish_size(topic: str, payload_len: int, qos: int = 1) -> int:
    """Bytes of an MQTT 3.1.1 PUBLISH packet: fixed header + topic + packet id + payload."""
    remaining = 2 + len(topic.encode()) + (2 if qos else 0) + payload_len
    return 1 + _varint_len(remaining) + remaining


def tls_overhead(version: str | None, cipher: str | None) -> int:
    if version == "TLSv1.3":
        return TLS_RECORD_OVERHEAD[("TLSv1.3", "*")]
    if cipher and "CHACHA20" in cipher:
        return TLS_RECORD_OVERHEAD[("TLSv1.2", "CHACHA20")]
    return TLS_RECORD_OVERHEAD[("TLSv1.2", "GCM")]
