// Page 6: benchmark results from bench/results (CSV), plus a quick run from here.
import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Gauge, RefreshCw } from "lucide-react";
import { Badge, Button, Card, CardHeader, cn } from "../components/ui";
import { Empty } from "../components/Feeds";
import { Term } from "../components/Term";
import { latestRun } from "./AttackConsole";
import type { LiveState } from "../live";

type Row = Record<string, string>;
type Results = {
  meta: { seconds?: number; started?: number; host?: string; machine?: string; profile?: { name: string } };
  bytes: Row[];
  latency: Row[];
  groups: Row[];
  drop: Row[];
  crypto: Record<string, Row[]>;
};
type BenchData = { full: Results; quick: Results };

const C = {
  plain: "#8b97b0",
  tls: "#60a5fa",
  ours: "#34d399",
  centralized: "#60a5fa",
  decentralized: "#34d399",
  grid: "#263049",
  text: "#8b97b0",
};
const tooltip = {
  contentStyle: { background: "#121826", border: "1px solid #263049", borderRadius: 8 },
  labelStyle: { color: "#e6ebf5" },
};
const axis = { stroke: C.text, fontSize: 13 };

function useBench(refreshKey: unknown) {
  const [data, setData] = useState<BenchData | null>(null);
  useEffect(() => {
    fetch("/api/bench")
      .then((r) => r.json())
      .then(setData)
      .catch(() => setData(null));
  }, [refreshKey]);
  return data;
}

function Chart({ title, note, children }: { title: string; note?: string; children: React.ReactNode }) {
  return (
    <Card className="flex flex-col">
      <CardHeader title={title} right={note && <span className="text-[13px] text-muted">{note}</span>} />
      <div className="h-72 p-3">{children}</div>
    </Card>
  );
}

function BytesChart({ rows }: { rows: Row[] }) {
  const kinds = [...new Set(rows.map((r) => r.kind))];
  const data = kinds.map((k) => {
    const pick = (m: string) => Number(rows.find((r) => r.kind === k && r.mode === m)?.wire_bytes ?? 0);
    return { kind: k, plain: pick("plain"), tls: pick("tls"), ours: pick("ours") };
  });
  const tls = rows.find((r) => r.mode === "tls")?.tls;
  return (
    <Chart title="Bytes per message (on the wire)" note={tls ? `MQTT packet + ${tls} record` : undefined}>
      <ResponsiveContainer>
        <BarChart data={data}>
          <CartesianGrid stroke={C.grid} vertical={false} />
          <XAxis dataKey="kind" {...axis} />
          <YAxis {...axis} unit=" B" />
          <Tooltip {...tooltip} cursor={{ fill: "#ffffff10" }} />
          <Legend />
          <Bar dataKey="plain" fill={C.plain} name="plain MQTT" />
          <Bar dataKey="tls" fill={C.tls} name="TLS only" />
          <Bar dataKey="ours" fill={C.ours} name="ours (broker-blind)" />
        </BarChart>
      </ResponsiveContainer>
    </Chart>
  );
}

function LatencyChart({ rows }: { rows: Row[] }) {
  const kinds = [...new Set(rows.map((r) => r.kind))];
  const data = kinds.map((k) => {
    const out: Record<string, number | string> = { kind: k };
    for (const m of ["plain", "tls", "ours"]) {
      const r = rows.find((x) => x.kind === k && x.mode === m);
      out[m] = Number(r?.median_ms ?? 0);
      out[`${m}_p95`] = Number(r?.p95_ms ?? 0);
    }
    return out;
  });
  const n = rows[0]?.n;
  return (
    <Chart title="Latency per message (median)" note={n ? `publish → received, n=${n} each` : undefined}>
      <ResponsiveContainer>
        <BarChart data={data}>
          <CartesianGrid stroke={C.grid} vertical={false} />
          <XAxis dataKey="kind" {...axis} />
          <YAxis {...axis} unit=" ms" />
          <Tooltip
            {...tooltip}
            cursor={{ fill: "#ffffff10" }}
            formatter={(v: number, name: string, item) => {
              const key = String(item.dataKey);
              const p95 = (item.payload as Record<string, number>)[`${key}_p95`];
              return [`${v.toFixed(3)} ms (p95 ${p95?.toFixed(3)})`, name];
            }}
          />
          <Legend />
          <Bar dataKey="plain" fill={C.plain} name="plain MQTT" />
          <Bar dataKey="tls" fill={C.tls} name="TLS only" />
          <Bar dataKey="ours" fill={C.ours} name="ours (broker-blind)" />
        </BarChart>
      </ResponsiveContainer>
    </Chart>
  );
}

const METRICS = [
  { id: "admin_ms", label: "time at KDC / MLS admin", unit: " ms" },
  { id: "member_ms", label: "time for one member", unit: " ms" },
  { id: "messages", label: "messages published", unit: "" },
  { id: "bytes", label: "bytes published", unit: " B" },
];

function GroupsChart({ rows }: { rows: Row[] }) {
  const [metric, setMetric] = useState("admin_ms");
  const m = METRICS.find((x) => x.id === metric)!;
  const sizes = [...new Set(rows.map((r) => Number(r.size)))].sort((a, b) => a - b);
  return (
    <Card className="flex flex-col xl:col-span-2">
      <CardHeader
        title="Join / revoke / rekey vs group size — centralized (KDC) vs decentralized (MLS)"
        right={
          <div className="flex rounded-lg border border-line bg-panel-2 p-0.5">
            {METRICS.map((x) => (
              <button
                key={x.id}
                onClick={() => setMetric(x.id)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-[13px] font-semibold",
                  metric === x.id ? "bg-panel text-fg shadow" : "text-muted hover:text-fg",
                )}
              >
                {x.label}
              </button>
            ))}
          </div>
        }
      />
      <div className="grid grid-cols-1 gap-2 p-3 md:grid-cols-3">
        {["join", "revoke", "rekey"].map((op) => {
          const data = sizes.map((size) => {
            const pick = (mode: string) => {
              const r = rows.find((x) => x.op === op && x.mode === mode && Number(x.size) === size);
              return r ? Number(r[metric]) : undefined;
            };
            return { size, centralized: pick("centralized"), decentralized: pick("decentralized") };
          });
          return (
            <div key={op} className="h-64">
              <div className="mb-1 text-center text-[14px] font-bold uppercase tracking-wider text-muted">{op}</div>
              <ResponsiveContainer>
                <LineChart data={data}>
                  <CartesianGrid stroke={C.grid} />
                  <XAxis dataKey="size" {...axis} scale="log" domain={["auto", "auto"]} type="number" ticks={sizes} />
                  <YAxis
                    {...axis}
                    scale="log"
                    domain={[(lo: number) => lo / 1.6, (hi: number) => hi * 1.6]}
                    unit={m.unit}
                    width={72}
                    tickFormatter={(v: number) => (v >= 100 ? v.toFixed(0) : String(+v.toPrecision(2)))}
                    allowDataOverflow
                  />
                  <Tooltip {...tooltip} labelFormatter={(s) => `${s} members`} />
                  <Legend />
                  <Line dataKey="centralized" stroke={C.centralized} strokeWidth={2.5} dot={{ r: 4 }} connectNulls />
                  <Line dataKey="decentralized" stroke={C.decentralized} strokeWidth={2.5} dot={{ r: 4 }} connectNulls />
                </LineChart>
              </ResponsiveContainer>
            </div>
          );
        })}
      </div>
      <p className="px-4 pb-3 text-[14px] text-muted">
        Log scales. The KDC sends one wrapped key per member (N messages); MLS sends one commit everyone
        downloads (+ a welcome when someone joins). Member time: unwrapping the key (KDC) vs processing the
        commit (MLS).
      </p>
    </Card>
  );
}

function DropChart({ rows }: { rows: Row[] }) {
  const data = rows
    .filter((r) => r.detect_s)
    .map((r) => ({ run: `run ${r.run}`, seconds: Number(r.detect_s), check: r.check }));
  const avg = data.length ? data.reduce((a, b) => a + b.seconds, 0) / data.length : null;
  return (
    <Chart
      title="Time to detect a dropped smoke alarm"
      note={avg != null ? `mean ${avg.toFixed(1)} s over ${data.length} run(s)` : undefined}
    >
      {data.length ? (
        <ResponsiveContainer>
          <BarChart data={data}>
            <CartesianGrid stroke={C.grid} vertical={false} />
            <XAxis dataKey="run" {...axis} />
            <YAxis {...axis} unit=" s" />
            <Tooltip
              {...tooltip}
              cursor={{ fill: "#ffffff10" }}
              formatter={(v: number, _n, item) => [`${v} s via ${(item.payload as { check: string }).check}`, "detected"]}
            />
            <Bar dataKey="seconds" fill="#fbbf24" />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <Empty text="No drop runs yet (needs security ON)." />
      )}
    </Chart>
  );
}

function CryptoTable({ crypto }: { crypto: Record<string, Row[]> }) {
  const hosts = Object.entries(crypto);
  const ops = hosts.length ? hosts[0][1].map((r) => r.op) : [];
  return (
    <Card className="xl:col-span-2">
      <CardHeader title="Crypto operation timings (median µs)" />
      <div className="overflow-x-auto p-3">
        {hosts.length ? (
          <table className="w-full text-[15px]">
            <thead>
              <tr className="text-left text-[13px] uppercase tracking-wider text-muted">
                <th className="px-3 py-2">Operation</th>
                {hosts.map(([tag, rows]) => (
                  <th key={tag} className="px-3 py-2 text-right">
                    {rows[0]?.host ?? tag}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ops.map((op) => (
                <tr key={op} className="border-t border-line">
                  <td className="px-3 py-1.5">{op}</td>
                  {hosts.map(([tag, rows]) => {
                    const r = rows.find((x) => x.op === op);
                    return (
                      <td key={tag} className="px-3 py-1.5 text-right font-mono">
                        {r ? Number(r.median_us).toFixed(1) : "—"}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty text="No crypto timings yet." />
        )}
      </div>
    </Card>
  );
}

export function Benchmarks({
  live,
  run,
  busy,
}: {
  live: LiveState;
  run: (name: string) => Promise<unknown>;
  busy: string | null;
}) {
  const lines = useMemo(() => latestRun(live.console, "bench.quick").map((l) => l.line), [live.console]);
  const done = lines.some((l) => l.includes("[bench] done"));
  const data = useBench(done ? lines.length : 0);
  const hasFull = !!data?.full.groups.length;
  const [source, setSource] = useState<"full" | "quick" | null>(null);
  const shown = source ?? (hasFull ? "full" : "quick");
  const res = data?.[shown];
  const meta = res?.meta;

  return (
    <div className="feed h-full space-y-4 overflow-y-auto p-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3 px-4 py-3">
          <Gauge className="h-6 w-6 text-accent" />
          <div className="flex rounded-lg border border-line bg-panel-2 p-0.5">
            {(["full", "quick"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSource(s)}
                className={cn(
                  "rounded-md px-3 py-1 text-[14px] font-semibold",
                  shown === s ? "bg-panel text-fg shadow" : "text-muted hover:text-fg",
                )}
              >
                {s === "full" ? "Full run (bbiot bench full)" : "Latest quick run"}
              </button>
            ))}
          </div>
          {meta?.started ? (
            <span className="text-[14px] text-muted">
              {new Date(meta.started * 1000).toLocaleString()} · {meta.host} · {meta.seconds} s
            </span>
          ) : (
            <Badge tone="muted">no {shown} results yet</Badge>
          )}
          <Button
            className="ml-auto"
            onClick={() => {
              setSource("quick");
              run("bench.quick");
            }}
            disabled={!!busy}
            title="bbiot bench quick"
          >
            <RefreshCw className={cn("h-4 w-4", busy === "bench.quick" && "animate-spin")} />
            {busy === "bench.quick" ? "Running…" : "Run quick benchmark"}
          </Button>
        </div>
        {(lines.length > 0 || busy === "bench.quick") && (
          <div className="mx-4 mb-4 overflow-hidden rounded-lg border border-line">
            <Term lines={lines} placeholder="$ bbiot bench quick" className="h-56 bg-[#05070c] px-2 py-1" />
          </div>
        )}
      </Card>

      {res ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {res.bytes.length ? <BytesChart rows={res.bytes} /> : null}
          {res.latency.length ? <LatencyChart rows={res.latency} /> : null}
          {res.groups.length ? <GroupsChart rows={res.groups} /> : null}
          <DropChart rows={res.drop} />
          <Card className="p-4 text-[15px] leading-relaxed text-fg/85">
            <div className="mb-2 font-bold uppercase tracking-wider text-muted">How these were measured</div>
            <ul className="list-disc space-y-1 pl-5">
              <li>Messages go through a separate benchmark Mosquitto (plain and mTLS listeners), one in flight.</li>
              <li>"Ours" includes sealing at the sender and every receive check (tag, topic, replay, time).</li>
              <li>Commands carry an Ed25519 signature; state updates are AEAD only.</li>
              <li>Group numbers use simulated members with the real KDC code and real OpenMLS commits.</li>
              <li>Drop detection runs attack 5 against the live home (needs security ON).</li>
            </ul>
          </Card>
          <CryptoTable crypto={res.crypto} />
        </div>
      ) : (
        <Card className="p-6 text-muted">Loading results…</Card>
      )}
    </div>
  );
}
