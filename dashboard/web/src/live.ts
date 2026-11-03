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
  cert: { status: "trusted" | "pending" | "invalid" | "unverified"; detail: string; leaf_index?: number };
  peers: Record<string, { status: string; fingerprint?: string; reason?: string }>;
};
export type DeviceSnap = {
  id: string;
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
  security?: string;
};
export type ConsoleLine = { run: string; action: string; line: string };

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
};

const MAX = 150;
const cap = <T,>(list: T[]) => (list.length > MAX ? list.slice(-MAX) : list);

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
      };
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
      return { ...state, console: cap([...state.console, msg as unknown as ConsoleLine]) };
    case "action_done":
      return msg.result ? { ...state, results: [...state.results, msg.result] } : state;
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

export type ActionResponse = { command: string; result?: AttackResult; error?: string };

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
