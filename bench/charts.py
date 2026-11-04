"""Matplotlib charts from the result CSVs (PNG, for the report). The dashboard draws
its own interactive charts from the same CSVs."""

from __future__ import annotations

from pathlib import Path

from bench.common import Emit, read_csv, results_dir


def render(emit: Emit, src: Path | None = None) -> list[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        emit("[bench] charts skipped: matplotlib not installed (uv sync --extra bench)")
        return []

    src = src or results_dir()
    outdir = src / "charts"
    outdir.mkdir(exist_ok=True)
    written: list[Path] = []

    def save(fig, name: str) -> None:
        path = outdir / name
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        written.append(path)

    colors = {
        "plain": "#9ca3af",
        "tls": "#60a5fa",
        "ours": "#34d399",
        "centralized": "#60a5fa",
        "decentralized": "#34d399",
    }

    # bytes per message
    rows = read_csv(src / "message_bytes.csv")
    if rows:
        kinds = sorted({r["kind"] for r in rows})
        modes = ["plain", "tls", "ours"]
        fig, ax = plt.subplots(figsize=(7, 4))
        width = 0.25
        for i, mode in enumerate(modes):
            vals = [
                next(int(r["wire_bytes"]) for r in rows if r["kind"] == k and r["mode"] == mode)
                for k in kinds
            ]
            ax.bar(
                [x + i * width for x in range(len(kinds))],
                vals,
                width,
                label=mode,
                color=colors[mode],
            )
        ax.set_xticks([x + width for x in range(len(kinds))], kinds)
        ax.set_ylabel("bytes on the wire per message")
        ax.set_title("Bytes per message (MQTT packet + TLS record)")
        ax.legend()
        save(fig, "message_bytes.png")

    # latency
    rows = read_csv(src / "message_latency.csv")
    if rows:
        kinds = sorted({r["kind"] for r in rows})
        fig, ax = plt.subplots(figsize=(7, 4))
        width = 0.25
        for i, mode in enumerate(["plain", "tls", "ours"]):
            sel = [next(r for r in rows if r["kind"] == k and r["mode"] == mode) for k in kinds]
            med = [float(r["median_ms"]) for r in sel]
            p95 = [float(r["p95_ms"]) - float(r["median_ms"]) for r in sel]
            ax.bar(
                [x + i * width for x in range(len(kinds))],
                med,
                width,
                yerr=[[0] * len(p95), p95],
                capsize=4,
                label=mode,
                color=colors[mode],
            )
        ax.set_xticks([x + width for x in range(len(kinds))], kinds)
        ax.set_ylabel("publish → received (ms), median, bar to p95")
        ax.set_title("Per-message latency through the broker")
        ax.legend()
        save(fig, "message_latency.png")

    # group operations vs size
    rows = read_csv(src / "groups.csv")
    if rows:
        for metric, label, fname in (
            ("admin_ms", "time at KDC / MLS admin (ms)", "rekey_time.png"),
            ("bytes", "bytes published", "rekey_bytes.png"),
            ("messages", "messages published", "rekey_messages.png"),
        ):
            fig, axes = plt.subplots(1, 3, figsize=(12, 3.8), sharey=True)
            for ax, op in zip(axes, ("join", "revoke", "rekey"), strict=True):
                for mode in ("centralized", "decentralized"):
                    pts = sorted(
                        (int(r["size"]), float(r[metric]))
                        for r in rows
                        if r["mode"] == mode and r["op"] == op
                    )
                    if pts:
                        ax.plot(*zip(*pts, strict=True), marker="o", label=mode, color=colors[mode])
                ax.set_xscale("log")
                ax.set_yscale("log")
                ax.set_title(op)
                ax.set_xlabel("group size")
            axes[0].set_ylabel(label)
            axes[0].legend()
            save(fig, fname)

    # drop detection
    rows = read_csv(src / "drop_detection.csv")
    vals = [float(r["detect_s"]) for r in rows if r.get("detect_s")]
    if vals:
        fig, ax = plt.subplots(figsize=(6, 3.5))
        ax.bar(range(1, len(vals) + 1), vals, color="#fbbf24")
        ax.set_xlabel("run")
        ax.set_ylabel("seconds until the hub alerted")
        ax.set_title("Time to detect a dropped smoke alarm")
        save(fig, "drop_detection.png")

    # crypto timings per machine (laptop vs Raspberry Pi, when both were measured)
    hosts = {f.stem.removeprefix("crypto-"): read_csv(f) for f in sorted(src.glob("crypto-*.csv"))}
    if hosts:
        ops = [r["op"] for r in next(iter(hosts.values()))]
        fig, ax = plt.subplots(figsize=(9, 0.42 * len(ops) + 1.5))
        height = 0.8 / len(hosts)
        for i, (tag, hrows) in enumerate(hosts.items()):
            by_op = {r["op"]: float(r["median_us"]) for r in hrows}
            ax.barh(
                [y + i * height for y in range(len(ops))],
                [by_op.get(o, 0) for o in ops],
                height,
                label=hrows[0]["host"] if hrows else tag,
            )
        ax.set_yticks([y + height * (len(hosts) - 1) / 2 for y in range(len(ops))], ops)
        ax.invert_yaxis()
        ax.set_xscale("log")
        ax.set_xlabel("µs per operation (median, log scale)")
        ax.set_title("Crypto operation timings")
        ax.legend()
        save(fig, "crypto.png")

    for p in written:
        emit(f"[bench] chart → {p.as_posix()}")
    return written
