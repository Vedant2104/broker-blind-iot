// Page 5: pairing a new device, step by step, and a counterfeit device stopping at
// the certificate check. Every step is the same code `bbiot pair` / `bbiot admin
// approve` / `bbiot attack counterfeit` runs.
import { useMemo } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Check, Loader2, Play, Skull, X } from "lucide-react";
import { Badge, Button, Card, CardHeader, cn } from "../components/ui";
import { Term } from "../components/Term";
import { ApprovalButtons } from "./KeysTrust";
import { latestRun } from "./AttackConsole";
import type { ActionResponse, AttackResult, LiveState } from "../live";

type Run = (name: string, params?: Record<string, unknown>) => Promise<ActionResponse>;

export type PairFlow = {
  kind: "real" | "counterfeit";
  device: string;
  running: boolean;
  startEpoch: number | null;
  wasMember?: boolean; // re-pairing a device already in the group: no rekey happens
  actionId?: string;
  requestCode?: string;
  deviceCode?: string;
  fingerprint?: string;
  codesConfirmed?: boolean;
  error?: string;
  result?: AttackResult;
};

type StepState = "todo" | "active" | "done" | "failed";

const STEPS = [
  "Device found",
  "Verify certificate",
  "Compare QR fingerprint",
  "Admin approvals",
  "Added to group",
  "Rekey complete",
];

function StepIcon({ state, n }: { state: StepState; n: number }) {
  const base = "flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 text-[16px] font-bold";
  if (state === "done") return <div className={cn(base, "border-ok bg-ok/20 text-ok")}><Check className="h-5 w-5" /></div>;
  if (state === "failed") return <div className={cn(base, "border-bad bg-bad/25 text-bad")}><X className="h-5 w-5" /></div>;
  if (state === "active")
    return (
      <div className={cn(base, "border-accent text-accent")}>
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    );
  return <div className={cn(base, "border-line text-muted")}>{n}</div>;
}

function Step({
  n,
  state,
  title,
  children,
}: {
  n: number;
  state: StepState;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex gap-4 rounded-xl border px-4 py-3",
        state === "failed" ? "border-bad bg-bad/10" : state === "done" ? "border-ok/40" : "border-line",
        state === "todo" && "opacity-50",
      )}
    >
      <StepIcon state={state} n={n} />
      <div className="min-w-0 flex-1">
        <div className={cn("text-[18px] font-bold", state === "failed" && "text-bad")}>{title}</div>
        {children && <div className="mt-1 text-[15px] text-fg/85">{children}</div>}
      </div>
    </div>
  );
}

export function Pairing({
  live,
  run,
  busy,
  flow,
  setFlow,
}: {
  live: LiveState;
  run: Run;
  busy: string | null;
  flow: PairFlow | null;
  setFlow: (f: PairFlow | null | ((f: PairFlow | null) => PairFlow | null)) => void;
}) {
  const candidates = Object.values(live.devices)
    .filter((d) => d.identity && d.kind !== "hub" && d.kind !== "app")
    .sort((a, b) => Number(a.identity?.cert.status === "trusted") - Number(b.identity?.cert.status === "trusted"));
  const defaultDevice =
    candidates.find((d) => d.identity?.cert.status !== "trusted")?.id ?? "garage-lock";
  const commissioned = live.devices[defaultDevice]?.identity?.cert.status === "trusted";
  const pendingRemovals = (live.trust.actions ?? []).filter(
    (a) => a.device === defaultDevice && a.type === "remove-device" && a.status === "pending",
  );
  const consoleUp = live.services["admin-console"] === "up";

  const start = async (device: string) => {
    const members =
      live.keymode === "decentralized" ? (live.trust.mls?.members ?? []) : (live.trust.kdc?.members ?? []);
    const wasMember =
      members.includes(device) && live.devices[device]?.identity?.cert.status === "trusted";
    setFlow({ kind: "real", device, running: true, startEpoch: live.epoch, wasMember });
    const res = await run("pair.start", { device });
    setFlow((f) =>
      f && f.kind === "real"
        ? res.error
          ? { ...f, running: false, error: res.error }
          : {
              ...f,
              running: false,
              actionId: res.data?.action_id,
              requestCode: res.data?.request_code,
              deviceCode: res.data?.device_code,
              fingerprint: res.data?.fingerprint,
            }
        : f,
    );
  };

  const counterfeit = async () => {
    setFlow({ kind: "counterfeit", device: "counterfeit", running: true, startEpoch: live.epoch });
    const res = await run("attack.counterfeit");
    setFlow((f) =>
      f && f.kind === "counterfeit" ? { ...f, running: false, result: res.result, error: res.error } : f,
    );
  };

  const terminal = useMemo(() => {
    const action = flow?.kind === "counterfeit" ? "attack.counterfeit" : "pair.start";
    const lines = latestRun(live.console, action);
    if (flow?.kind !== "real") return lines.map((l) => l.line);
    const approvals = live.console.filter(
      (c) => c.action === "admin.approve" && flow.actionId && c.line.includes(flow.actionId),
    );
    const runs = new Set(approvals.map((c) => c.run));
    return [...lines, ...live.console.filter((c) => runs.has(c.run))].map((l) => l.line);
  }, [live.console, flow]);

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-4 overflow-y-auto p-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Card>
          <CardHeader title="Pair a device" />
          <div className="flex flex-wrap items-center gap-3 p-4">
            <span className="text-muted">New device:</span>
            <span className="font-mono text-[17px] font-bold">{defaultDevice}</span>
            <Button onClick={() => start(defaultDevice)} disabled={!!busy} title={`bbiot pair --device ${defaultDevice}`}>
              <Play className="h-4 w-4" /> Start pairing
            </Button>
            <Button variant="danger" onClick={counterfeit} disabled={!!busy} title="bbiot attack counterfeit">
              <Skull className="h-4 w-4" /> Counterfeit device tries to join
            </Button>
            {flow && !flow.running && (
              <Button variant="ghost" onClick={() => setFlow(null)}>
                Clear
              </Button>
            )}
          </div>
          {commissioned && (
            <div className="space-y-2 border-t border-line px-4 py-3 text-[15px]">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-warn">
                  {defaultDevice} is already commissioned. One live certificate per device key: revoke it
                  first to pair it again.
                </span>
                <Button
                  variant="outline"
                  onClick={() => run("pair.revoke", { device: defaultDevice })}
                  disabled={!!busy || pendingRemovals.length > 0}
                  title={`bbiot revoke --device ${defaultDevice}`}
                >
                  Revoke {defaultDevice}
                </Button>
              </div>
              {pendingRemovals.map((a) => (
                <div key={a.id} className="flex flex-wrap items-center gap-3">
                  <span>
                    Remove {a.device} <span className="font-mono text-[13px] text-muted">{a.id}</span> ·{" "}
                    {a.approvals.length}/{live.trust.threshold ?? 2}
                  </span>
                  <ApprovalButtons action={a} run={run} busy={busy} consoleUp={consoleUp} />
                </div>
              ))}
            </div>
          )}
        </Card>

        {flow ? (
          flow.kind === "real" ? (
            <RealSteps flow={flow} setFlow={setFlow} live={live} run={run} busy={busy} />
          ) : (
            <CounterfeitSteps flow={flow} />
          )
        ) : (
          <Card className="p-6 text-muted">
            Start pairing to walk through: device found → certificate request verified → QR fingerprint
            compared → 2 of 3 admins approve → device joins the group → group rekeyed.
          </Card>
        )}
      </div>

      <Card className="flex min-h-[420px] flex-col overflow-hidden">
        <CardHeader title="Terminal" right={<span className="text-[13px] text-muted">same commands as the CLI</span>} />
        <Term
          lines={terminal}
          placeholder="$ bbiot pair --device garage-lock"
          className="min-h-0 flex-1 bg-[#05070c] px-2 py-1"
        />
      </Card>
    </div>
  );
}

function RealSteps({
  flow,
  setFlow,
  live,
  run,
  busy,
}: {
  flow: PairFlow;
  setFlow: (f: PairFlow | null | ((f: PairFlow | null) => PairFlow | null)) => void;
  live: LiveState;
  run: Run;
  busy: string | null;
}) {
  const failedAt = flow.error ? (/DIFFER/.test(flow.error) ? 3 : flow.actionId ? 4 : 2) : 0;
  const action = (live.trust.actions ?? []).find((a) => a.id === flow.actionId);
  const need = live.trust.threshold ?? 2;
  const approved = !!action && action.status !== "pending";
  const dev = live.devices[flow.device];
  const certTrusted = dev?.identity?.cert.status === "trusted";
  const mlsMode = live.keymode === "decentralized";
  const members = mlsMode ? (live.trust.mls?.members ?? []) : (live.trust.kdc?.members ?? []);
  const inGroup = approved && certTrusted && members.includes(flow.device);
  const devEpoch = mlsMode ? dev?.groups?.decentralized?.epoch : dev?.groups?.centralized?.epoch ?? dev?.group?.epoch;
  const rekeyed =
    inGroup &&
    live.epoch != null &&
    devEpoch === live.epoch &&
    (flow.wasMember || flow.startEpoch == null || live.epoch > flow.startEpoch);
  const consoleUp = live.services["admin-console"] === "up";

  const state = (n: number): StepState => {
    if (failedAt === n) return "failed";
    if (failedAt && n > failedAt) return "todo";
    const done = [
      false,
      !!flow.actionId,
      !!flow.actionId,
      !!flow.codesConfirmed,
      approved,
      inGroup,
      rekeyed,
    ][n];
    if (done) return "done";
    const prevDone = n === 1 || state(n - 1) === "done";
    return prevDone && (flow.running || n > 2) ? "active" : "todo";
  };

  return (
    <div className="space-y-2">
      <Step n={1} state={state(1)} title={STEPS[0]}>
        {flow.device} on the local pairing channel; it generated its own Ed25519 + X25519 keys.
      </Step>
      <Step n={2} state={state(2)} title={STEPS[1]}>
        {failedAt === 2 ? (
          <span className="text-bad">✗ {flow.error}</span>
        ) : (
          "Certificate signing request: Ed25519 proof of possession ✓, name matches ✓"
        )}
      </Step>
      <Step n={3} state={state(3)} title={STEPS[2]}>
        {flow.deviceCode && flow.requestCode ? (
          <div className="flex flex-wrap items-center gap-6">
            <div className="rounded-lg bg-white p-2">
              <QRCodeSVG value={flow.deviceCode} size={112} />
            </div>
            <div className="space-y-1">
              <div className="text-[13px] text-muted">QR on the device</div>
              <div className="font-mono text-[18px] font-bold">{flow.deviceCode}</div>
              <div className="text-[13px] text-muted">Computed from the request</div>
              <div className="font-mono text-[18px] font-bold">{flow.requestCode}</div>
              {flow.deviceCode === flow.requestCode ? (
                flow.codesConfirmed ? (
                  <Badge tone="ok">✓ codes match</Badge>
                ) : (
                  <Button className="mt-1" onClick={() => setFlow((f) => (f ? { ...f, codesConfirmed: true } : f))}>
                    <Check className="h-4 w-4" /> Codes match
                  </Button>
                )
              ) : (
                <Badge tone="bad">✗ codes differ — request swapped</Badge>
              )}
            </div>
          </div>
        ) : failedAt === 3 ? (
          <span className="text-bad">✗ {flow.error}</span>
        ) : (
          "Compare the code shown on the device with the one computed from its request."
        )}
      </Step>
      <Step n={4} state={state(4)} title={STEPS[3]}>
        {failedAt === 4 && <div className="text-bad">✗ {flow.error}</div>}
        {action ? (
          <div className="flex flex-wrap items-center gap-3">
            <Badge tone={approved ? "ok" : "warn"}>
              {approved ? "approved · root signed the certificate" : `${action.approvals.length}/${need} signatures`}
            </Badge>
            {!approved && flow.codesConfirmed && (
              <ApprovalButtons action={action} run={run} busy={busy} consoleUp={consoleUp} />
            )}
            {!consoleUp && !approved && (
              <span className="text-[14px] text-warn">
                admin console offline — run <code>bbiot admin approve --admin A --action {action.id}</code>
              </span>
            )}
          </div>
        ) : flow.actionId ? (
          `action ${flow.actionId} posted…`
        ) : (
          "Any 2 of admins A, B, C sign; then the offline root issues the certificate."
        )}
      </Step>
      <Step n={5} state={state(5)} title={STEPS[4]}>
        {inGroup
          ? `${flow.device} is trusted and a member of the ${mlsMode ? "MLS group" : "KDC group"}.`
          : approved
            ? `waiting for ${flow.device} to fetch its certificate and join (${mlsMode ? "MLS add" : "signed KDC key exchange"})…`
            : `Certificate published in the transparency log; ${flow.device} joins the group.`}
      </Step>
      <Step n={6} state={state(6)} title={STEPS[5]}>
        {rekeyed && flow.wasMember
          ? `${flow.device} was already a member with these keys (re-pair), so no rekey was needed — epoch ${live.epoch}. Revoke it first (bbiot revoke --device ${flow.device}) to see a fresh join.`
          : rekeyed
            ? `epoch ${flow.startEpoch ?? "?"} → ${live.epoch}: fresh group key; the new device cannot read older traffic.`
            : "New epoch with a fresh group key."}
      </Step>
    </div>
  );
}

function CounterfeitSteps({ flow }: { flow: PairFlow }) {
  const stages = flow.result?.details?.stages ?? [];
  const done = !flow.running;
  const unlocked = flow.result?.outcome === "SUCCEEDED";
  return (
    <div className="space-y-2">
      <Step n={1} state="done" title={STEPS[0]}>
        An unknown device announces itself as a new lock.
      </Step>
      <Step n={2} state={done ? "failed" : "active"} title={STEPS[1]}>
        {done ? (
          <>
            <div className="font-semibold text-bad">
              ✗ Stopped: no certificate signed by the bbiot root{flow.error ? ` (${flow.error})` : ""}
            </div>
            <ul className="mt-1 space-y-0.5 font-mono text-[13px]">
              {stages.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
            {unlocked && (
              <div className="mt-2 rounded-lg bg-warn/15 px-3 py-2 text-warn">
                Security is OFF: by bypassing the hub it still unlocked a door. Turn security ON and try again.
              </div>
            )}
          </>
        ) : (
          "checking…"
        )}
      </Step>
      {STEPS.slice(2).map((t, i) => (
        <Step key={t} n={i + 3} state="todo" title={t} />
      ))}
    </div>
  );
}
