// Page 3: the tmux layout of scripts/demo-tmux.sh, live: broker spy, attacker,
// a device's log, hub alerts. Read-only (no shell in the browser).
import { useMemo, useState } from "react";
import { Card, cn } from "../components/ui";
import { Term } from "../components/Term";
import { CopyButton } from "./AttackConsole";
import type { LiveState } from "../live";

const SOURCES = [
  "front-door",
  "back-door",
  "thermostat",
  "smoke-kitchen",
  "phone",
  "garage-lock",
  "hub",
  "evil-broker",
  "kdc",
];

// Hub lines worth an operator's attention (the full hub log is in the device pane).
const HUB_ALERT = /✗|⚠|alert|quarantin|late|missing|dropped|gap|block|violat|revok|rekey|counterfeit/i;

function Pane({
  title,
  command,
  lines,
  right,
  className,
}: {
  title: string;
  command: string;
  lines: string[];
  right?: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("flex min-h-0 min-w-0 flex-col overflow-hidden", className)}>
      <div className="flex items-center gap-3 border-b border-line px-3 py-2">
        <span className="shrink-0 text-[14px] font-bold uppercase tracking-wider text-muted">{title}</span>
        <code className="min-w-0 flex-1 truncate font-mono text-[13px] text-accent" title={command}>
          $ {command}
        </code>
        {right}
        <CopyButton text={command} className="shrink-0" />
      </div>
      <Term lines={lines} placeholder="waiting for output…" className="min-h-0 flex-1 bg-[#05070c] px-2 py-1" />
    </Card>
  );
}

export function TerminalPage({ live }: { live: LiveState }) {
  const [source, setSource] = useState("front-door");

  const spy = useMemo(
    () => live.brokerFeed.map((m) => `[spy] ${m.topic}  ${m.size}B  ${m.payload}`),
    [live.brokerFeed],
  );
  const attacker = useMemo(
    () => live.console.filter((c) => !c.action.startsWith("phone.")).map((c) => c.line),
    [live.console],
  );
  const device = live.logs[source] ?? [];
  const hub = useMemo(() => (live.logs["hub"] ?? []).filter((l) => HUB_ALERT.test(l)), [live.logs]);

  const deviceCmd = `docker compose logs -f ${source}`;

  return (
    <div className="grid h-full min-h-0 grid-cols-2 grid-rows-2 gap-4 p-4">
      <Pane title="Broker spy" command="bbiot spy --topic 'home/#'" lines={spy} />
      <Pane
        title="Attacker"
        command="bbiot attack …   # commands run from the dashboard, with output"
        lines={attacker}
      />
      <Pane
        title="Device log"
        command={deviceCmd}
        lines={device}
        right={
          <select
            value={source}
            onChange={(e) => setSource(e.target.value)}
            className="shrink-0 rounded-md border border-line bg-panel-2 px-2 py-1 text-[14px]"
            aria-label="Which component's log"
          >
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        }
      />
      <Pane title="Hub alerts" command="docker compose logs -f hub | grep -E '✗|alert|quarantin|late|missing'" lines={hub} />
    </div>
  );
}
