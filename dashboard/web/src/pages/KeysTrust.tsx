// Page 4: what the key directory serves and whether it checks out, the transparency
// log, the group (KDC members or MLS tree), and pending admin approvals.
import { AlertTriangle, KeyRound, ScrollText, ShieldCheck } from "lucide-react";
import { Badge, Button, Card, CardHeader, cn } from "../components/ui";
import { Empty } from "../components/Feeds";
import { fmtTime, type AdminAction, type LiveState, type TrustRow } from "../live";

type Run = (name: string, params?: Record<string, unknown>) => Promise<unknown>;

const rowTone = { verified: "ok", revoked: "warn", "key-changed": "bad", invalid: "bad" } as const;
const rowLabel = {
  verified: "in log ✓",
  revoked: "revoked",
  "key-changed": "KEY CHANGED",
  invalid: "FAILED",
} as const;

const certTone: Record<string, "ok" | "warn" | "bad" | "muted"> = {
  trusted: "ok",
  pending: "warn",
  unverified: "warn",
  revoked: "bad",
  invalid: "bad",
};

const short = (s?: string, n = 23) => (s ? (s.length > n ? s.slice(0, n) + "…" : s) : "—");

function DirectoryTable({ rows, live }: { rows: TrustRow[]; live: LiveState }) {
  return (
    <Card className="flex min-h-0 flex-col">
      <CardHeader
        title="Key directory (untrusted)"
        right={<span className="text-[13px] text-muted">each entry verified like a device would</span>}
      />
      <div className="feed min-h-0 overflow-auto p-2">
        <table className="w-full text-[15px]">
          <thead>
            <tr className="text-left text-[13px] uppercase tracking-wider text-muted">
              <th className="px-3 py-2">Device</th>
              <th className="px-3 py-2">Fingerprint</th>
              <th className="px-3 py-2">Cert (device's view)</th>
              <th className="px-3 py-2">Root · log inclusion</th>
              <th className="px-3 py-2">Pin</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const own = live.devices[r.device]?.identity?.cert;
              return (
                <tr key={r.device} className="border-t border-line">
                  <td className="px-3 py-2 font-semibold">{r.device}</td>
                  <td className="px-3 py-2 font-mono text-[13px] text-fg/80" title={r.fingerprint}>
                    {short(r.fingerprint)}
                  </td>
                  <td className="px-3 py-2">
                    {own ? (
                      <Badge tone={certTone[own.status] ?? "muted"} title={own.detail}>
                        {own.status}
                      </Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={rowTone[r.status]} title={r.detail}>
                      {rowLabel[r.status]}
                      {r.status === "verified" && r.leaf_index != null && ` · leaf #${r.leaf_index}`}
                    </Badge>
                    {r.status !== "verified" && (
                      <div className="mt-1 max-w-md text-[13px] text-bad/90">{r.detail}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-[14px] text-muted">{r.pin ?? "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!rows.length && <Empty text="Waiting for the directory…" />}
      </div>
    </Card>
  );
}

function LogCard({ live, run, busy }: { live: LiveState; run: Run; busy: string | null }) {
  const sth = live.trust.sth;
  const check = live.logCheck;
  return (
    <Card>
      <CardHeader
        title="Transparency log"
        right={
          <Button
            variant="outline"
            className="px-2.5 py-1.5 text-[14px]"
            onClick={() => run("log.verify")}
            disabled={!!busy}
            title="bbiot log verify"
          >
            <ScrollText className="h-4 w-4" />
            {busy === "log.verify" ? "Verifying…" : "Verify consistency"}
          </Button>
        }
      />
      <div className="space-y-2 p-4 text-[15px]">
        <div className="flex justify-between">
          <span className="text-muted">Tree size</span>
          <span className="font-mono text-[18px] font-bold">{sth?.tree_size ?? "—"}</span>
        </div>
        <div className="flex justify-between gap-4">
          <span className="text-muted">Signed tree head</span>
          <span className="truncate font-mono text-[13px]" title={sth?.root_hash}>
            {sth ? sth.root_hash.slice(0, 32) + "…" : "—"}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted">Signed at</span>
          <span className="font-mono text-[13px]">{sth ? fmtTime(sth.timestamp_ms / 1000) : "—"}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted">Signature</span>
          <span className={sth ? "text-ok" : "text-muted"}>
            {sth ? "✓ log key certified by the root" : "—"}
          </span>
        </div>
        {check && (
          <div
            className={cn(
              "rounded-lg px-3 py-2 font-semibold",
              check.ok ? "bg-ok/15 text-ok" : "bg-bad/15 text-bad",
            )}
          >
            {check.ok ? "✓" : "✗"} Last check {fmtTime(check.ts)}:{" "}
            {check.ok ? "consistent, every entry included" : "problems found — see the terminal"}
          </div>
        )}
      </div>
    </Card>
  );
}

/** RFC 9420 tree: 2^k leaves (blanks padded), direct path of the committer to the root. */
function MlsTree({ members, committer }: { members: string[]; committer: string }) {
  let leaves = 1;
  while (leaves < Math.max(members.length, 2)) leaves *= 2;
  const depth = Math.log2(leaves);
  const W = 640;
  const H = 70 + depth * 70;
  const xOf = (level: number, j: number) => ((j + 0.5) * W) / (leaves >> level);
  const yOf = (level: number) => H - 40 - level * 70;
  const ci = members.indexOf(committer);
  const onPath = (level: number, j: number) => ci >= 0 && j === ci >> level;

  const nodes: React.ReactNode[] = [];
  for (let level = depth; level >= 0; level--) {
    const count = leaves >> level;
    for (let j = 0; j < count; j++) {
      const x = xOf(level, j);
      const y = yOf(level);
      const hot = onPath(level, j);
      if (level > 0) {
        for (const child of [2 * j, 2 * j + 1]) {
          const childHot = hot && onPath(level - 1, child);
          nodes.push(
            <line
              key={`e${level}-${j}-${child}`}
              x1={x}
              y1={y}
              x2={xOf(level - 1, child)}
              y2={yOf(level - 1)}
              stroke={childHot ? "var(--color-ok)" : "var(--color-line)"}
              strokeWidth={childHot ? 4 : 2}
            />,
          );
        }
      }
    }
  }
  for (let level = depth; level >= 0; level--) {
    const count = leaves >> level;
    for (let j = 0; j < count; j++) {
      const x = xOf(level, j);
      const y = yOf(level);
      const hot = onPath(level, j);
      const name = level === 0 ? members[j] : undefined;
      const blank = level === 0 && !name;
      nodes.push(
        <g key={`n${level}-${j}`}>
          <circle
            cx={x}
            cy={y}
            r={level === 0 ? 10 : 12}
            fill={hot ? "var(--color-ok)" : blank ? "var(--color-bg)" : "var(--color-panel-2)"}
            stroke={hot ? "var(--color-ok)" : "var(--color-line)"}
            strokeWidth={2}
            strokeDasharray={blank ? "3 3" : undefined}
          />
          {level === 0 && (
            <text
              x={x}
              y={y + 30}
              textAnchor="middle"
              fontSize={13}
              fill={hot ? "var(--color-ok)" : name ? "var(--color-fg)" : "var(--color-muted)"}
            >
              {name ?? "blank"}
            </text>
          )}
          {level === depth && (
            <text x={x} y={y - 20} textAnchor="middle" fontSize={13} fill="var(--color-muted)">
              root (group secret)
            </text>
          )}
        </g>,
      );
    }
  }
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="MLS ratchet tree">
      {nodes}
    </svg>
  );
}

function GroupCard({ live }: { live: LiveState }) {
  const mlsMode = live.keymode === "decentralized";
  const { kdc, mls } = live.trust;
  return (
    <Card>
      <CardHeader
        title={mlsMode ? "Group · MLS (TreeKEM)" : "Group · KDC (centralized)"}
        right={
          <Badge tone="accent">
            epoch {mlsMode ? (mls?.epoch ?? "—") : (kdc?.epoch ?? "—")}
          </Badge>
        }
      />
      <div className="p-4">
        {mlsMode ? (
          mls ? (
            <>
              <MlsTree members={mls.members} committer={mls.admin} />
              <p className="mt-2 text-[14px] text-muted">
                Green: the committer's ({mls.admin}) direct path — the nodes that get fresh secrets on
                every commit (add / remove / update). {mls.members.length} members. Leaves are drawn in
                member order. The directory only stores key packages; it never sees a group secret.
              </p>
            </>
          ) : (
            <Empty text="No MLS group yet." />
          )
        ) : kdc ? (
          <>
            <div className="flex flex-wrap gap-2">
              {kdc.members.map((m) => (
                <Badge key={m} tone="ok">
                  {m}
                </Badge>
              ))}
              {kdc.revoked.map((m) => (
                <Badge key={m} tone={kdc.members.includes(m) ? "muted" : "bad"}>
                  {m} · {kdc.members.includes(m) ? "revoked earlier, re-paired" : "revoked"}
                </Badge>
              ))}
            </div>
            <table className="mt-4 w-full text-[14px]">
              <thead>
                <tr className="text-left text-[12px] uppercase tracking-wider text-muted">
                  <th className="py-1">Epoch</th>
                  <th className="py-1">Why</th>
                  <th className="py-1 text-right">Members</th>
                  <th className="py-1 text-right">Rekey time</th>
                </tr>
              </thead>
              <tbody>
                {[...kdc.history].reverse().map((h) => (
                  <tr key={h.epoch} className="border-t border-line">
                    <td className="py-1 font-mono">{h.epoch}</td>
                    <td className="py-1">{h.reason}</td>
                    <td className="py-1 text-right">{h.members.length}</td>
                    <td className="py-1 text-right font-mono">{h.ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-[14px] text-muted">
              The KDC knows every group key — the trade-off attack 10 shows.
            </p>
          </>
        ) : (
          <Empty text="KDC unreachable." />
        )}
      </div>
    </Card>
  );
}

export function ApprovalButtons({
  action,
  run,
  busy,
  consoleUp,
}: {
  action: AdminAction;
  run: Run;
  busy: string | null;
  consoleUp: boolean;
}) {
  return (
    <div className="flex gap-1.5">
      {["A", "B", "C"].map((admin) => {
        const signed = action.approvals.includes(admin);
        return (
          <Button
            key={admin}
            variant={signed ? "ghost" : "outline"}
            className={cn("px-2.5 py-1 text-[14px]", signed && "text-ok")}
            disabled={signed || action.status !== "pending" || !!busy || !consoleUp}
            onClick={() => run("admin.approve", { admin, action: action.id })}
            title={
              !consoleUp
                ? "admin console offline — use: bbiot admin approve"
                : `bbiot admin approve --admin ${admin} --action ${action.id}`
            }
          >
            {signed ? "✓ " : ""}Admin {admin}
          </Button>
        );
      })}
    </div>
  );
}

function ApprovalsCard({ live, run, busy }: { live: LiveState; run: Run; busy: string | null }) {
  const actions = live.trust.actions ?? [];
  const need = live.trust.threshold ?? 2;
  const consoleUp = live.services["admin-console"] === "up";
  return (
    <Card className="flex min-h-0 flex-col">
      <CardHeader
        title="Admin approvals (2 of 3)"
        right={
          <Badge tone={consoleUp ? "ok" : "bad"} title="the admins' signing station">
            <KeyRound className="h-3.5 w-3.5" /> admin console {consoleUp ? "online" : "offline"}
          </Badge>
        }
      />
      <div className="feed min-h-0 space-y-2 overflow-y-auto p-3">
        {actions.map((a) => (
          <div key={a.id} className="rounded-lg bg-panel-2 px-3 py-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="font-semibold">
                  {a.type === "add-device" ? "Add" : "Remove"} {a.device}
                </span>{" "}
                <span className="font-mono text-[13px] text-muted">{a.id}</span>
              </div>
              <Badge tone={a.status === "pending" ? "warn" : "ok"}>
                {a.status === "pending" ? `${a.approvals.length}/${need} signatures` : a.status}
              </Badge>
            </div>
            {a.status === "pending" && (
              <div className="mt-2">
                <ApprovalButtons action={a} run={run} busy={busy} consoleUp={consoleUp} />
              </div>
            )}
          </div>
        ))}
        {!actions.length && <Empty text="No admin actions yet. Start one on the Pairing page." />}
      </div>
    </Card>
  );
}

export function KeysTrust({ live, run, busy }: { live: LiveState; run: Run; busy: string | null }) {
  const rows = live.trust.directory ?? [];
  const bad = rows.filter((r) => r.status === "key-changed" || r.status === "invalid");
  const incidents = live.trust.incidents ?? [];
  const logBad = live.trust.log_error || live.logCheck?.ok === false || incidents.length > 0;
  return (
    <div className="feed flex h-full flex-col gap-4 overflow-y-auto p-4">
      {(bad.length > 0 || logBad) && (
        <div className="flex items-start gap-3 rounded-xl border-2 border-bad bg-bad/15 px-5 py-4 text-bad">
          <AlertTriangle className="mt-0.5 h-7 w-7 shrink-0" />
          <div>
            <div className="text-[20px] font-extrabold">Key directory mismatch detected</div>
            {bad.map((r) => (
              <div key={r.device} className="text-[15px]">
                now · {r.device}: {r.detail}
              </div>
            ))}
            {incidents.map((i) => (
              <div key={i.ts + i.subject} className="text-[15px]">
                {fmtTime(i.ts)} · {i.subject}: {i.detail}
              </div>
            ))}
            <div className="mt-1 text-[13px] text-bad/80">Stays until “Reset demo”.</div>
            {live.trust.log_error && <div className="text-[15px]">log: {live.trust.log_error}</div>}
            {live.logCheck?.ok === false && (
              <div className="text-[15px]">`bbiot log verify` found problems (see Terminal / Attack Console).</div>
            )}
          </div>
        </div>
      )}
      {!bad.length && !logBad && rows.length > 0 && (
        <div className="flex items-center gap-2 text-[15px] text-ok">
          <ShieldCheck className="h-5 w-5" /> All {rows.length} directory entries are root-signed, in the
          log and match their pins.
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <DirectoryTable rows={rows} live={live} />
        <LogCard live={live} run={run} busy={busy} />
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <GroupCard live={live} />
        <ApprovalsCard live={live} run={run} busy={busy} />
      </div>
    </div>
  );
}
