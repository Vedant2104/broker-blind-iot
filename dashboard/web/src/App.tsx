import { TopBar } from "./components/TopBar";
import { DeviceCard, PhoneControls } from "./components/Devices";
import { BrokerFeed, DeviceFeed } from "./components/Feeds";
import { AlertTimeline, AttackPanel } from "./components/SidePanels";
import { cn } from "./components/ui";
import { useLive, useRunner } from "./live";

const PAGES = [
  { name: "Live Home", phase: 1 },
  { name: "Attack Console", phase: 7 },
  { name: "Terminal", phase: 7 },
  { name: "Keys & Trust", phase: 7 },
  { name: "Pairing", phase: 7 },
  { name: "Benchmarks", phase: 8 },
];

const ORDER = ["phone", "front-door", "back-door", "thermostat", "smoke-kitchen", "garage-lock"];

export default function App() {
  const live = useLive();
  const { busy, last, run } = useRunner();
  const devices = ORDER.map((id) => live.devices[id]).filter(Boolean);

  return (
    <div className="flex h-full flex-col">
      <TopBar
        live={live}
        busy={busy}
        onReset={() => run("demo.reset")}
        onVerifyLog={() => run("log.verify")}
      />

      <nav className="flex gap-1 border-b border-line bg-panel px-4">
        {PAGES.map((p) => (
          <span
            key={p.name}
            title={p.phase > 1 ? `Arrives in phase ${p.phase}` : undefined}
            className={cn(
              "border-b-2 px-4 py-2.5 text-[15px] font-semibold",
              p.phase === 1 ? "border-accent text-fg" : "border-transparent text-muted/50",
            )}
          >
            {p.name}
          </span>
        ))}
        {last?.error && <span className="ml-auto self-center text-[14px] text-bad">✗ {last.error}</span>}
      </nav>

      <main className="grid min-h-0 flex-1 overflow-hidden grid-cols-[minmax(320px,1fr)_minmax(0,2.2fr)_minmax(340px,1.2fr)] gap-4 p-4">
        <section className="feed min-h-0 min-w-0 space-y-3 overflow-y-auto pr-1">
          {devices.map((d) => (
            <DeviceCard key={d.id} d={d}>
              {d.id === "phone" && <PhoneControls run={run} busy={busy} />}
            </DeviceCard>
          ))}
          {!devices.length && <div className="p-6 text-muted">Waiting for devices…</div>}
        </section>

        <section className="grid min-h-0 min-w-0 grid-cols-2 gap-4">
          <BrokerFeed items={live.brokerFeed} />
          <DeviceFeed items={live.deviceFeed} />
        </section>

        <section className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] gap-4">
          <AttackPanel run={run} busy={busy} results={live.results} console={live.console} />
          <AlertTimeline alerts={live.alerts} />
        </section>
      </main>
    </div>
  );
}
