import { useEffect, useState } from "react";
import { TopBar } from "./components/TopBar";
import { DeviceCard, PhoneControls } from "./components/Devices";
import { BrokerFeed, DeviceFeed } from "./components/Feeds";
import { AlertTimeline, AttackPanel } from "./components/SidePanels";
import { cn } from "./components/ui";
import { useLive, useRunner, type LiveState } from "./live";
import { AttackConsole } from "./pages/AttackConsole";
import { TerminalPage } from "./pages/TerminalPage";
import { KeysTrust } from "./pages/KeysTrust";
import { Pairing, type PairFlow } from "./pages/Pairing";

const PAGES = [
  { id: "home", name: "Live Home" },
  { id: "attacks", name: "Attack Console" },
  { id: "terminal", name: "Terminal" },
  { id: "keys", name: "Keys & Trust" },
  { id: "pairing", name: "Pairing" },
  { id: "bench", name: "Benchmarks", phase: 8 },
];

const ORDER = ["hub", "phone", "front-door", "back-door", "thermostat", "smoke-kitchen", "garage-lock"];

function usePage() {
  const read = () => {
    const id = location.hash.replace(/^#\/?/, "");
    return PAGES.some((p) => p.id === id && !p.phase) ? id : "home";
  };
  const [page, setPage] = useState(read);
  useEffect(() => {
    const onHash = () => setPage(read());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return page;
}

type Runner = ReturnType<typeof useRunner>;

function LiveHome({ live, run, busy }: { live: LiveState; run: Runner["run"]; busy: string | null }) {
  const devices = ORDER.map((id) => live.devices[id]).filter(Boolean);
  return (
    <div className="grid h-full min-h-0 grid-cols-[minmax(320px,1fr)_minmax(0,2.2fr)_minmax(340px,1.2fr)] gap-4 overflow-hidden p-4">
      <section className="feed min-h-0 min-w-0 space-y-3 overflow-y-auto pr-1">
        {devices.map((d) => (
          <DeviceCard key={d.id} d={d} hub={live.devices["hub"]}>
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
    </div>
  );
}

export default function App() {
  const live = useLive();
  const { busy, last, run } = useRunner();
  const page = usePage();
  const [pairFlow, setPairFlow] = useState<PairFlow | null>(null);

  return (
    <div className="flex h-full flex-col">
      <TopBar
        live={live}
        busy={busy}
        onReset={() => run("demo.reset")}
        onVerifyLog={() => run("log.verify")}
        onSecurity={(mode) => run(`security.${mode}`)}
        onKeymode={(mode) => run(`keymode.${mode}`)}
      />

      <nav className="flex gap-1 border-b border-line bg-panel px-4">
        {PAGES.map((p) =>
          p.phase ? (
            <span
              key={p.id}
              title={`Arrives in phase ${p.phase}`}
              className="border-b-2 border-transparent px-4 py-2.5 text-[15px] font-semibold text-muted/50"
            >
              {p.name}
            </span>
          ) : (
            <a
              key={p.id}
              href={`#/${p.id}`}
              className={cn(
                "border-b-2 px-4 py-2.5 text-[15px] font-semibold",
                page === p.id ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg",
              )}
            >
              {p.name}
            </a>
          ),
        )}
        {last?.error && <span className="ml-auto self-center truncate text-[14px] text-bad">✗ {last.error}</span>}
      </nav>

      <main className="min-h-0 flex-1 overflow-hidden">
        {page === "home" && <LiveHome live={live} run={run} busy={busy} />}
        {page === "attacks" && <AttackConsole live={live} run={run} busy={busy} />}
        {page === "terminal" && <TerminalPage live={live} />}
        {page === "keys" && <KeysTrust live={live} run={run} busy={busy} />}
        {page === "pairing" && (
          <Pairing live={live} run={run} busy={busy} flow={pairFlow} setFlow={setPairFlow} />
        )}
      </main>
    </div>
  );
}
