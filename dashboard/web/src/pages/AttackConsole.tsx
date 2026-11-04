// Page 2: the 10 attacks, each with its exact command, a live terminal and the result,
// plus a matrix of results per security / key mode.
import { useMemo, useState } from "react";
import { Check, Copy, Skull } from "lucide-react";
import { Badge, Button, Card, CardHeader, cn } from "../components/ui";
import { Term } from "../components/Term";
import { ATTACKS, outcomeLabel, outcomeTone, resultKey, type AttackDef } from "../attacks";
import type { AttackResult, ConsoleLine, LiveState } from "../live";

type Run = (name: string, params?: Record<string, unknown>) => Promise<unknown>;

export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className={cn("flex items-center gap-1 text-[13px] text-muted hover:text-fg", className)}
      title="Copy command"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setDone(true);
        window.setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className="h-3.5 w-3.5" />}
      {done ? "copied" : "copy"}
    </button>
  );
}

/** Lines of the latest run of one dashboard action. */
export function latestRun(console: ConsoleLine[], action: string): ConsoleLine[] {
  let run: string | null = null;
  for (let i = console.length - 1; i >= 0; i--) {
    if (console[i].action === action) {
      run = console[i].run;
      break;
    }
  }
  return run ? console.filter((c) => c.run === run) : [];
}

function AttackCard({
  a,
  live,
  run,
  busy,
}: {
  a: AttackDef;
  live: LiveState;
  run: Run;
  busy: string | null;
}) {
  const action = `attack.${a.id}`;
  const lines = useMemo(() => latestRun(live.console, action).map((l) => l.line), [live.console, action]);
  const result = [...live.results].reverse().find((r) => r.attack === resultKey(a.id));
  // the command actually run (from the terminal), else the one that would run now
  const command = lines[0]?.startsWith("$ ") ? lines[0].slice(2) : a.command(live.security);
  const running = busy === action;

  return (
    <Card className="flex min-w-0 flex-col">
      <div className="flex items-start gap-3 border-b border-line px-4 py-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-panel-2 text-[17px] font-extrabold text-muted">
          {a.n}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[17px] font-bold">{a.name}</span>
            <Badge tone="muted" className="text-[12px]">
              {a.attacker}
            </Badge>
          </div>
          <div className="mt-0.5 text-[14px] text-muted">{a.hint}</div>
        </div>
        <Button
          variant="danger"
          className="shrink-0"
          onClick={() => run(action)}
          disabled={!!busy}
          title={`Launch: ${command}`}
        >
          <Skull className="h-4 w-4" />
          {running ? "Running…" : "Launch"}
        </Button>
      </div>

      <div className="flex items-center gap-2 px-4 py-2">
        {result ? (
          <Badge tone={outcomeTone[result.outcome]} className="shrink-0">
            {outcomeLabel[result.outcome]} · {result.security?.toUpperCase()} ·{" "}
            {result.keymode === "decentralized" ? "MLS" : "KDC"}
          </Badge>
        ) : (
          <Badge tone="muted">not run yet</Badge>
        )}
        <span className="min-w-0 truncate text-[13px] text-muted" title={result?.reason}>
          {result?.reason}
        </span>
      </div>

      <div className="mx-4 mb-4 overflow-hidden rounded-lg border border-line">
        <div className="flex items-center justify-between gap-2 border-b border-line bg-black/50 px-3 py-1.5">
          <code className="truncate font-mono text-[13px] text-accent">$ {command}</code>
          <CopyButton text={command} className="shrink-0" />
        </div>
        <Term
          lines={lines}
          placeholder="# press Launch, or copy the command above into a terminal"
          className="h-48 bg-[#05070c] px-2 py-1"
        />
      </div>
    </Card>
  );
}

const MODES = [
  { security: "off", keymode: "centralized", label: "OFF · Centralized" },
  { security: "off", keymode: "decentralized", label: "OFF · Decentralized" },
  { security: "on", keymode: "centralized", label: "ON · Centralized" },
  { security: "on", keymode: "decentralized", label: "ON · Decentralized" },
];

function ResultsMatrix({ results, live }: { results: AttackResult[]; live: LiveState }) {
  const cell = (id: string, security: string, keymode: string) =>
    [...results]
      .reverse()
      .find((r) => r.attack === resultKey(id) && r.security === security && r.keymode === keymode);
  return (
    <Card>
      <CardHeader
        title="Results: attack × mode"
        right={<span className="text-[13px] text-muted">fills in as attacks run · latest run per cell</span>}
      />
      <div className="overflow-x-auto p-3">
        <table className="w-full border-separate border-spacing-1 text-[15px]">
          <thead>
            <tr>
              <th className="px-3 py-2 text-left text-[13px] font-bold uppercase tracking-wider text-muted">
                Attack
              </th>
              {MODES.map((m) => {
                const now = live.security === m.security && live.keymode === m.keymode;
                return (
                  <th
                    key={m.label}
                    className={cn(
                      "rounded-md px-3 py-2 text-center text-[13px] font-bold uppercase tracking-wider",
                      now ? "bg-accent/15 text-accent" : "text-muted",
                    )}
                    title={now ? "current mode" : undefined}
                  >
                    {m.label}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {ATTACKS.map((a) => (
              <tr key={a.id}>
                <td className="whitespace-nowrap rounded-md bg-panel-2 px-3 py-2 font-semibold">
                  {a.n}. {a.name}
                </td>
                {MODES.map((m) => {
                  const r = cell(a.id, m.security, m.keymode);
                  return (
                    <td
                      key={m.label}
                      title={r?.reason}
                      className={cn(
                        "rounded-md px-3 py-2 text-center font-bold",
                        !r && "bg-panel-2 text-muted/50",
                        r?.outcome === "SUCCEEDED" && "bg-bad/15 text-bad",
                        r?.outcome === "BLOCKED" && "bg-ok/15 text-ok",
                        r?.outcome === "DETECTED" && "bg-warn/15 text-warn",
                      )}
                    >
                      {r ? (r.outcome === "SUCCEEDED" ? "✗ " : "✓ ") + outcomeLabel[r.outcome] : "—"}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function AttackConsole({ live, run, busy }: { live: LiveState; run: Run; busy: string | null }) {
  return (
    <div className="feed h-full space-y-4 overflow-y-auto p-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {ATTACKS.map((a) => (
          <AttackCard key={a.id} a={a} live={live} run={run} busy={busy} />
        ))}
      </div>
      <ResultsMatrix results={live.results} live={live} />
    </div>
  );
}
