import { useState } from "react";
import { DoorClosed, DoorOpen, Flame, Smartphone, Thermometer } from "lucide-react";
import { Badge, Button, Card, cn } from "./ui";
import type { DeviceSnap } from "../live";

type Run = (name: string, params?: Record<string, unknown>) => Promise<unknown>;

function describe(d: DeviceSnap): { text: string; tone: "ok" | "bad" | "warn" | "muted" } {
  const s = d.state ?? {};
  switch (d.kind) {
    case "lock":
      return s.locked ? { text: "Locked", tone: "ok" } : { text: "UNLOCKED", tone: "bad" };
    case "thermostat":
      return {
        text: `${Number(s.temperature).toFixed(1)}°C → set ${Number(s.setpoint).toFixed(1)}°C`,
        tone: Number(s.setpoint) > 28 ? "warn" : "ok",
      };
    case "smoke":
      return s.alarm ? { text: "SMOKE ALARM", tone: "bad" } : { text: "No smoke", tone: "ok" };
    case "app":
      return { text: `${s.alarms_received ?? 0} alarm(s) received`, tone: "muted" };
    default:
      return { text: "—", tone: "muted" };
  }
}

function Icon({ d }: { d: DeviceSnap }) {
  const cls = "h-7 w-7 text-muted";
  if (d.kind === "lock") return d.state?.locked ? <DoorClosed className={cls} /> : <DoorOpen className="h-7 w-7 text-bad" />;
  if (d.kind === "thermostat") return <Thermometer className={cls} />;
  if (d.kind === "smoke") return <Flame className={cn(cls, Boolean(d.state?.alarm) && "text-bad")} />;
  return <Smartphone className={cls} />;
}

const toneText = { ok: "text-ok", bad: "text-bad", warn: "text-warn", muted: "text-muted" };

export function DeviceCard({ d, children }: { d: DeviceSnap; children?: React.ReactNode }) {
  const online = d.reachable && d.connected;
  const { text, tone } = describe(d);
  return (
    <Card className="p-4">
      <div className="flex items-start gap-3">
        <Icon d={d} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <div className="truncate font-bold">{d.label ?? d.id}</div>
            <Badge tone="warn" title="Device certificates arrive in phase 2">
              Unverified
            </Badge>
          </div>
          <div key={text} className={cn("flash mt-1 rounded text-[22px] font-extrabold", toneText[tone])}>
            {online ? text : "offline"}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-muted">
            <span>
              heartbeat: <span className="text-muted/70">n/a (phase 6)</span>
            </span>
            <span>
              key: <span className="font-mono">—</span>
            </span>
            <span className={online ? "text-ok" : "text-bad"}>{online ? "● online" : "● offline"}</span>
          </div>
        </div>
      </div>
      {children}
    </Card>
  );
}

export function PhoneControls({ run, busy }: { run: Run; busy: string | null }) {
  const [setpoint, setSetpoint] = useState(22);
  const b = (name: string) => busy === name;
  return (
    <div className="mt-4 grid grid-cols-2 gap-2">
      <Button onClick={() => run("phone.unlock_front")} disabled={!!busy}>
        {b("phone.unlock_front") ? "…" : "Unlock Front Door"}
      </Button>
      <Button variant="outline" onClick={() => run("phone.lock_front")} disabled={!!busy}>
        Lock Front Door
      </Button>
      <div className="col-span-2 flex gap-2">
        <input
          type="number"
          min={5}
          max={35}
          step={0.5}
          value={setpoint}
          onChange={(e) => setSetpoint(Number(e.target.value))}
          className="w-24 rounded-lg border border-line bg-panel-2 px-3 py-2 text-[16px]"
          aria-label="Thermostat setpoint"
        />
        <Button
          variant="outline"
          className="flex-1"
          onClick={() => run("phone.set_thermostat", { setpoint })}
          disabled={!!busy || setpoint < 5 || setpoint > 35}
        >
          Set Thermostat
        </Button>
      </div>
      <Button
        variant="outline"
        className="col-span-2"
        onClick={() => run("phone.test_smoke")}
        disabled={!!busy}
      >
        Test Smoke Alarm
      </Button>
      <Button variant="ghost" onClick={() => run("phone.lock_back")} disabled={!!busy} className="col-span-2 text-[14px]">
        Lock Back Door
      </Button>
    </div>
  );
}
