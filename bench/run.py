"""Benchmark profiles: `bbiot bench quick` (about a minute, for the dashboard button)
and `bbiot bench full` (the numbers for the report)."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass

from bench import charts, crypto, drop, groups, messages
from bench.common import Emit, host_info, results_dir
from securelib.config import Config


@dataclass(frozen=True)
class Profile:
    name: str
    crypto_n: int
    messages_n: int
    sizes: tuple[int, ...]
    reps: int
    drop_runs: int


QUICK = Profile("quick", crypto_n=500, messages_n=50, sizes=(10, 100), reps=3, drop_runs=1)
FULL = Profile("full", crypto_n=5000, messages_n=300, sizes=(10, 100, 1000), reps=5, drop_runs=5)


def run(cfg: Config, emit: Emit, profile: Profile, *, identity: str) -> dict:
    quick = profile.name == "quick"
    out = results_dir(quick=quick)
    started = time.time()
    emit(f"[bench] profile {profile.name}: results → {out.as_posix()}")
    done: dict[str, str] = {}

    def step(name: str, fn) -> None:
        try:
            fn()
            done[name] = "ok"
        except Exception as exc:  # noqa: BLE001 - one failing part must not lose the rest
            done[name] = f"failed: {type(exc).__name__}: {exc}"
            emit(f"[bench] ✗ {name} {done[name]}")

    step("crypto", lambda: crypto.run(emit, profile.crypto_n, out / f"crypto-{_tag()}.csv"))
    step(
        "messages",
        lambda: messages.run(cfg, emit, identity=identity, n=profile.messages_n, out=out),
    )
    step("groups", lambda: groups.run(emit, list(profile.sizes), profile.reps, out))
    step("drop", lambda: drop.run(cfg, emit, profile.drop_runs, out))
    if not quick:
        step("charts", lambda: charts.render(emit, out))
    meta = {
        "profile": asdict(profile),
        **host_info(),
        "started": started,
        "seconds": round(time.time() - started, 1),
        "steps": done,
    }
    (out / "run.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    emit(f"[bench] done in {meta['seconds']} s")
    return meta


def _tag() -> str:
    return host_info()["machine"].lower().replace(" ", "-") or "host"
