"""Time to detect a dropped message: run attack 5 (broker drops the smoke alarm)
against the live stack several times and record when the hub raised the alarm and
which check caught it (end-to-end ack, sequence gap or missing heartbeat)."""

from __future__ import annotations

import time
from pathlib import Path

from bench.common import Emit, results_dir, write_csv
from cli import actions, remote
from securelib.config import Config

TOPIC = "home/smoke/kitchen"


def run(cfg: Config, emit: Emit, runs: int, out: Path | None = None) -> list[dict]:
    out = out or results_dir()
    security = actions.security_mode(cfg)
    if security != "on":
        emit(
            f"[bench] drop detection skipped: security is {security!r} "
            "(needs ON: `bbiot security on`)"
        )
        return []
    emit(f"[bench] drop detection: broker drops the smoke alarm, {runs} run(s)")
    rows = []
    for i in range(runs):
        result = actions.attack_drop(cfg, lambda _l: None, TOPIC)
        d = result.details
        rows.append(
            {
                "run": i + 1,
                "outcome": result.outcome,
                "check": d.get("check") or "",
                "detect_s": d.get("detect_s") if d.get("detect_s") is not None else "",
            }
        )
        emit(
            f"[bench]   run {i + 1}: {result.outcome}"
            + (f" via {d.get('check')} after {d.get('detect_s')} s" if d.get("detect_s") else "")
        )
        # let the alarm clear and the ack/heartbeat state settle before the next run
        remote.device_reset(cfg, "smoke-kitchen")
        time.sleep(3)
    write_csv(out / "drop_detection.csv", rows)
    emit(f"[bench] → {(out / 'drop_detection.csv').as_posix()}")
    return rows
