import { useState } from "react";
import { Copy, Skull } from "lucide-react";
import { Badge, Button, Card, CardHeader, cn } from "./ui";
import { Empty } from "./Feeds";
import { fmtTime, type Alert, type AttackResult, type ConsoleLine } from "../live";

const ATTACKS = [
  { id: "read", name: "1 · Read payloads", hint: "Broker reads every message" },
  { id: "modify", name: "2 · Modify setpoint", hint: "Phone asks 21°C, broker writes 30°C" },
  { id: "replay", name: "3 · Replay unlock", hint: "Re-send a captured 'unlock front door'" },
  { id: "redirect", name: "4 · Redirect", hint: "Front-door unlock → back door topic" },
  { id: "drop", name: "5 · Drop smoke alarm", hint: "Alarm silently discarded" },
];

const outcomeTone = { SUCCEEDED: "bad", BLOCKED: "ok", DETECTED: "warn" } as const;

export function AttackPanel({
  run,
  busy,
  results,
  console,
}: {
  run: (name: string) => Promise<unknown>;
  busy: string | null;
  results: AttackResult[];
  console: ConsoleLine[];
}) {
  const latest = (id: string) => [...results].reverse().find((r) => r.attack === id);
  const lastRun = console.length ? console[console.length - 1].run : null;
  const lines = console.filter((c) => c.run === lastRun);
  const command = lines[0]?.line.replace(/^\$ /, "");

  return (
    <Card className="flex min-h-0 min-w-0 flex-col overflow-hidden">
      <CardHeader title="Broker attacks" right={<span className="text-[13px] text-muted">6–10 in later phases</span>} />
      <div className="space-y-2 p-3">
        {ATTACKS.map((a) => {
          const r = latest(a.id);
          return (
            <div key={a.id} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2">
              <div className="min-w-0 flex-1">
                <div className="font-semibold">{a.name}</div>
                <div className="truncate text-[13px] text-muted" title={r?.reason ?? a.hint}>
                  {r ? r.reason : a.hint}
                </div>
              </div>
              {r && <Badge className="shrink-0" tone={outcomeTone[r.outcome]}>{r.outcome === "SUCCEEDED" ? "Succeeded" : r.outcome === "BLOCKED" ? "Blocked" : "Detected"}</Badge>}
              <Button
                variant="danger"
                className="shrink-0 px-2.5 py-1.5"
                onClick={() => run(`attack.${a.id}`)}
                disabled={!!busy}
                title={`Launch attack: ${a.name}`}
              >
                <Skull className="h-4 w-4" />
                {busy === `attack.${a.id}` ? "…" : "Launch"}
              </Button>
            </div>
          );
        })}
      </div>
      <div className="mx-3 mb-3 flex min-h-0 flex-1 flex-col rounded-lg border border-line bg-black/60">
        <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-[12px] text-muted">
          <span className="truncate font-mono">{command ?? "terminal"}</span>
          {command && (
            <button
              className="flex items-center gap-1 hover:text-fg"
              onClick={() => navigator.clipboard?.writeText(command)}
              title="Copy command"
            >
              <Copy className="h-3.5 w-3.5" /> copy
            </button>
          )}
        </div>
        <pre className="feed min-h-24 flex-1 overflow-auto whitespace-pre-wrap p-3 font-mono text-[13px] leading-relaxed text-fg/90">
          {lines.map((l) => l.line).join("\n") || "Launch an attack to see the exact bbiot command and its output."}
        </pre>
      </div>
    </Card>
  );
}

const sevStyle = {
  critical: "border-bad text-bad",
  warning: "border-warn text-warn",
  info: "border-accent text-accent",
};

export function AlertTimeline({ alerts }: { alerts: Alert[] }) {
  const [open, setOpen] = useState<number | null>(null);
  const items = [...alerts].reverse();
  return (
    <Card className="flex min-h-0 flex-col">
      <CardHeader title="Security alerts" right={<span className="text-[13px] text-muted">{alerts.length}</span>} />
      <div className="feed min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
        {items.map((a) => {
          const { id, ts, severity, title, ...rest } = a;
          return (
            <button
              key={id}
              onClick={() => setOpen(open === id ? null : id)}
              className={cn("block w-full rounded-lg border-l-4 bg-panel-2 px-3 py-2 text-left", sevStyle[severity])}
            >
              <div className="flex justify-between gap-2">
                <span className="font-semibold">{title}</span>
                <span className="shrink-0 text-[13px] text-muted">{fmtTime(ts)}</span>
              </div>
              {open === id && (
                <div className="mt-2 space-y-0.5 font-mono text-[13px] text-fg/80">
                  {Object.entries(rest).map(([k, v]) => (
                    <div key={k}>
                      <span className="text-muted">{k}:</span> {String(v)}
                    </div>
                  ))}
                </div>
              )}
            </button>
          );
        })}
        {!items.length && <Empty text="No alerts." />}
      </div>
    </Card>
  );
}
