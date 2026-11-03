import { Card, CardHeader, cn } from "./ui";
import { fmtTime, type BrokerItem, type DeviceEvent } from "../live";

// Feeds show the newest message first.
const newestFirst = <T,>(items: T[]) => [...items].reverse();

export function BrokerFeed({ items }: { items: BrokerItem[] }) {
  return (
    <Card className="flex min-h-0 flex-col">
      <CardHeader title="What the broker sees" right={<span className="text-[13px] text-muted">{items.length}</span>} />
      <div className="feed min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
        {newestFirst(items).map((m) => {
          const hex = m.payload.startsWith("hex:");
          return (
            <div key={`${m.ts}-${m.topic}-${m.size}`} className="flash rounded-lg bg-panel-2 px-3 py-2">
              <div className="flex items-center justify-between gap-2 text-[13px] text-muted">
                <span className="truncate font-mono text-accent">{m.topic}</span>
                <span className="shrink-0">
                  {m.size} B · {fmtTime(m.ts)}
                </span>
              </div>
              <div
                className={cn(
                  "mt-1 break-all font-mono text-[14px] leading-snug",
                  hex ? "text-muted" : "text-warn",
                )}
              >
                {m.payload}
              </div>
            </div>
          );
        })}
        {!items.length && <Empty text="No traffic yet." />}
      </div>
    </Card>
  );
}

function bodyText(e: DeviceEvent) {
  if (!e.body) return "";
  return Object.entries(e.body)
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" ");
}

export function DeviceFeed({ items }: { items: DeviceEvent[] }) {
  return (
    <Card className="flex min-h-0 flex-col">
      <CardHeader title="What the devices received" right={<span className="text-[13px] text-muted">{items.length}</span>} />
      <div className="feed min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
        {newestFirst(items).map((e) => {
          const ok = e.kind === "accepted";
          return (
            <div
              key={`${e.device}-${e.id}`}
              className={cn(
                "flash rounded-lg border-l-4 bg-panel-2 px-3 py-2",
                ok ? "border-ok" : "border-bad",
              )}
            >
              <div className="flex items-center justify-between gap-2 text-[13px] text-muted">
                <span>
                  <span className={cn("font-bold", ok ? "text-ok" : "text-bad")}>{ok ? "✓" : "✗"}</span>{" "}
                  <span className="font-semibold text-fg">{e.device}</span>
                  {e.sender && <> ← {e.sender}</>}
                  {e.seq != null && <> · seq {e.seq}</>}
                </span>
                <span className="shrink-0">{fmtTime(e.ts)}</span>
              </div>
              <div className="mt-1 font-mono text-[14px]">
                {ok ? bodyText(e) : <span className="text-bad">REJECTED: {e.reason}</span>}
              </div>
            </div>
          );
        })}
        {!items.length && <Empty text="Nothing received yet." />}
      </div>
    </Card>
  );
}

export function Empty({ text }: { text: string }) {
  return <div className="p-6 text-center text-muted">{text}</div>;
}
