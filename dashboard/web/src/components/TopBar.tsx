import { RotateCcw, ScrollText, ShieldOff, ShieldCheck } from "lucide-react";
import { Badge, Button, cn } from "./ui";
import { fmtTime, type LiveState } from "../live";

function Pill({ name, status }: { name: string; status?: string }) {
  const tone = status === "up" ? "ok" : status === "down" ? "bad" : "muted";
  return (
    <Badge tone={tone} title={`${name}: ${status ?? "not built yet"}`}>
      <span
        className={cn(
          "h-2 w-2 rounded-full",
          tone === "ok" ? "bg-ok" : tone === "bad" ? "bg-bad" : "bg-muted",
        )}
      />
      {name}
    </Badge>
  );
}

function Segmented({
  options,
  value,
  disabledReason,
  onPick,
  busy,
}: {
  options: string[];
  value: string;
  disabledReason?: string;
  onPick?: (option: string) => void;
  busy?: boolean;
}) {
  return (
    <div className="flex rounded-lg border border-line bg-panel-2 p-0.5" title={disabledReason}>
      {options.map((o) => {
        const active = o.toLowerCase() === value;
        return (
          <button
            key={o}
            disabled={!onPick || busy || active}
            onClick={() => onPick?.(o.toLowerCase())}
            className={cn(
              "rounded-md px-3 py-1 text-[14px] font-semibold",
              active ? "bg-panel text-fg shadow" : "text-muted hover:text-fg",
              !onPick && "opacity-60",
              active && o === "ON" && "text-ok",
              active && o === "OFF" && "text-bad",
              active && o === "Decentralized" && "text-ok",
            )}
          >
            {o}
          </button>
        );
      })}
    </div>
  );
}

export function TopBar({
  live,
  onReset,
  onVerifyLog,
  onSecurity,
  onKeymode,
  busy,
}: {
  live: LiveState;
  onReset: () => void;
  onVerifyLog: () => void;
  onSecurity: (mode: string) => void;
  onKeymode: (mode: string) => void;
  busy: string | null;
}) {
  const secure = live.security === "on";
  return (
    <header className="flex flex-wrap items-center gap-4 border-b border-line bg-panel px-5 py-3">
      <div className="mr-2 text-xl font-extrabold tracking-tight">Broker-Blind IoT</div>

      <div className="flex items-center gap-2">
        {secure ? (
          <ShieldCheck className="h-6 w-6 text-ok" />
        ) : (
          <ShieldOff className="h-6 w-6 text-bad" />
        )}
        <Segmented
          options={["OFF", "ON"]}
          value={live.security}
          onPick={onSecurity}
          busy={!!busy}
        />
        <span className="text-[14px] text-muted">{secure ? "broker-blind" : "TLS only"}</span>
      </div>

      <Segmented
        options={["Centralized", "Decentralized"]}
        value={live.keymode}
        onPick={onKeymode}
        busy={!!busy}
      />

      <div className="flex flex-wrap items-center gap-2">
        <Pill name="broker" status={live.services["broker"]} />
        <Pill name="evil-broker" status={live.services["evil-broker"]} />
        <Pill name="directory" status={live.services["directory"]} />
        <Pill
          name={`transparency log${live.logSize != null ? ` · ${live.logSize}` : ""}`}
          status={live.services["translog"]}
        />
        <Pill name="KDC" status={live.services["kdc"]} />
        <Pill name="admin console" status={live.services["admin-console"]} />
        <Badge tone="accent" title="current group key epoch (KDC epoch, or MLS epoch)">
          {live.keymode === "decentralized" ? "MLS" : "KDC"} epoch {live.epoch ?? "—"}
        </Badge>
        {!live.connected && <Badge tone="bad">dashboard offline</Badge>}
      </div>

      <div className="ml-auto flex items-center gap-2">
        {busy === "log.verify" ? (
          <Badge tone="muted">verifying…</Badge>
        ) : (
          live.logCheck && (
            <Badge
              tone={live.logCheck.ok ? "ok" : "bad"}
              title="Full output: Keys & Trust page, or the Terminal page (Attacker pane)"
            >
              {live.logCheck.ok ? "✓ log verified" : "✗ log problems"} · {fmtTime(live.logCheck.ts)}
            </Badge>
          )
        )}
        <Button variant="outline" onClick={onVerifyLog} disabled={!!busy} title="bbiot log verify">
          <ScrollText className="h-4 w-4" /> Verify log
        </Button>
      </div>
      <Button variant="outline" onClick={onReset} disabled={!!busy}>
        <RotateCcw className="h-4 w-4" /> Reset demo
      </Button>
    </header>
  );
}
