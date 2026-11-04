// Live state from the backend WebSocket, plus the action API.
import { useEffect, useReducer, useRef, useState } from "react";

export type BrokerItem = { ts: number; topic: string; size: number; payload: string };
export type DeviceEvent = {
  id: number;
  ts: number;
  device: string;
  kind: "accepted" | "rejected";
  topic: string;
  size: number;
  sender?: string;
  seq?: number;
  body?: Record<string, unknown>;
  reason?: string;
};
export type Alert = {
  id: number;
  ts: number;
  severity: "critical" | "warning" | "info";
  title: string;
  [key: string]: unknown;
};
export type TrustInfo = {
  fingerprint: string;
  pairing_code: string;
  cert: {
    status: "trusted" | "pending" | "invalid" | "revoked" | "unverified";
    detail: string;
    leaf_index?: number;
  };
  peers: Record<string, { status: string; fingerprint?: string; reason?: string }>;
};
export type DeviceSnap = {
  id: string;
  group?: { mode: string; epoch: number | null; session?: boolean; members?: string[] };
  groups?: Record<string, { mode: string; epoch: number | null; members?: string[]; admin?: string }>;
  keymode?: string;
  identity?: TrustInfo;
  kind?: string;
  label?: string;
  connected?: boolean;
  reachable: boolean;
  security?: string;
  state?: Record<string, unknown>;
};
export type AttackResult = {
  attack: string;
  outcome: "SUCCEEDED" | "BLOCKED" | "DETECTED";
  reason: string;
  command: string;
  details?: { stages?: string[]; [k: string]: unknown };
  security?: string;
  keymode?: string;
};
export type ConsoleLine = { run: string; action: string; line: string; ts?: number };

export type TrustRow = {
  device: string;
  fingerprint?: string;
  leaf_index?: number;
  status: "verified" | "revoked" | "key-changed" | "invalid";
  pin?: string;
  detail: string;
};
export type AdminAction = {
  id: string;
  type: "add-device" | "remove-device";
  device: string;
  status: string;
  approvals: string[];
  created_ms?: number;
};
export type TrustView = {
  ts?: number;
  directory?: TrustRow[];
  sth?: { tree_size: number; root_hash: string; timestamp_ms: number } | null;
  log_error?: string | null;
  actions?: AdminAction[];
  threshold?: number;
  kdc?: {
    epoch: number;
    members: string[];
    revoked: string[];
    history: { epoch: number; reason: string; members: string[]; ms: number }[];
  } | null;
  mls?: { epoch: number | null; members: string[]; admin: string; group_id: string | null } | null;
  console?: { admins: string[]; root: boolean } | null;
  incidents?: { subject: string; detail: string; ts: number }[];
};
export type LogCheck = { ok: boolean; ts: number } | null;

export type LiveState = {
  connected: boolean;
  security: string;
  keymode: string;
  epoch: number | null;
  logSize: number | null;
  services: Record<string, string>;
  devices: Record<string, DeviceSnap>;
  brokerFeed: BrokerItem[];
  deviceFeed: DeviceEvent[];
  alerts: Alert[];
  results: AttackResult[];
  console: ConsoleLine[];
  logs: Record<string, string[]>;
  trust: TrustView;
  logCheck: LogCheck;
};

const initial: LiveState = {
  connected: false,
  security: "off",
  keymode: "centralized",
  epoch: null,
  logSize: null,
  services: {},
  devices: {},
  brokerFeed: [],
  deviceFeed: [],
  alerts: [],
  results: [],
  console: [],
  logs: {},
  trust: {},
  logCheck: null,
};

const MAX = 150;
const cap = <T,>(list: T[], max = MAX) => (list.length > max ? list.slice(-max) : list);
const LOG_MAX = 400;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Msg = { type: string; [k: string]: any };

function reducer(state: LiveState, msg: Msg): LiveState {
  switch (msg.type) {
    case "_open":
      return { ...state, connected: true };
    case "_close":
      return { ...state, connected: false };
    case "snapshot":
      return {
        ...state,
        connected: true,
        security: msg.security,
        keymode: msg.keymode,
        epoch: msg.epoch,
        logSize: msg.log_size,
        services: msg.services,
        devices: msg.devices,
        brokerFeed: cap(msg.broker_feed),
        deviceFeed: cap(msg.device_feed),
        alerts: cap(msg.alerts),
        results: msg.results,
        console: cap(msg.console ?? [], 600),
        logs: Object.fromEntries(
          Object.entries((msg.logs ?? {}) as Record<string, { line: string }[]>).map(([k, v]) => [
            k,
            v.map((x) => x.line),
          ]),
        ),
        trust: msg.trust ?? {},
        logCheck: msg.log_check ?? null,
      };
    case "epoch":
      return { ...state, epoch: msg.epoch };
    case "log":
      return { ...state, logSize: msg.size };
    case "broker":
      return { ...state, brokerFeed: cap([...state.brokerFeed, msg.item]) };
    case "device_event":
      return { ...state, deviceFeed: cap([...state.deviceFeed, msg.item]) };
    case "device":
      return { ...state, devices: { ...state.devices, [msg.device.id]: msg.device } };
    case "alert":
      return { ...state, alerts: cap([...state.alerts, msg.alert]) };
    case "console":
      return { ...state, console: cap([...state.console, msg as unknown as ConsoleLine], 600) };
    case "logline": {
      const prev = state.logs[msg.source] ?? [];
      return {
        ...state,
        logs: { ...state.logs, [msg.source]: cap([...prev, ...(msg.lines as string[])], LOG_MAX) },
      };
    }
    case "trust":
      return { ...state, trust: msg.trust };
    case "action_done": {
      let next = state;
      if (msg.result)
        next = { ...next, results: [...next.results, msg.result] };
      if (msg.action === "demo.reset") next = { ...next, logCheck: null };
      if (msg.action === "log.verify" && typeof msg.ok === "boolean")
        next = { ...next, logCheck: { ok: msg.ok, ts: Date.now() / 1000 } };
      return next;
    }
    default:
      return state;
  }
}

export function useLive(): LiveState {
  const [state, dispatch] = useReducer(reducer, initial);
  const retry = useRef<number>();

  useEffect(() => {
    let socket: WebSocket | null = null;
    let closed = false;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${proto}://${location.host}/ws`);
      socket.onopen = () => dispatch({ type: "_open" });
      socket.onmessage = (e) => dispatch(JSON.parse(e.data));
      socket.onclose = () => {
        dispatch({ type: "_close" });
        if (!closed) retry.current = window.setTimeout(connect, 1500);
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry.current);
      socket?.close();
    };
  }, []);

  return state;
}

export type ActionResponse = {
  command: string;
  run?: string;
  result?: AttackResult;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data?: any;
  ok?: boolean;
  error?: string;
};

export async function runAction(
  name: string,
  params: Record<string, unknown> = {},
): Promise<ActionResponse> {
  const r = await fetch(`/api/actions/${name}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    return { command: "", error: detail || `HTTP ${r.status}` };
  }
  return data;
}

/** Track which action is running so buttons can disable themselves. */
export function useRunner() {
  const [busy, setBusy] = useState<string | null>(null);
  const [last, setLast] = useState<ActionResponse | null>(null);
  const run = async (name: string, params: Record<string, unknown> = {}) => {
    setBusy(name);
    try {
      const res = await runAction(name, params);
      setLast(res);
      return res;
    } finally {
      setBusy(null);
    }
  };
  return { busy, last, run };
}

export const fmtTime = (ts: number) =>
  new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
