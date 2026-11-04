// The 10 attacks: what each one does, who the attacker is, and the exact CLI command
// (the backend runs the same code path and echoes the same command).
export type AttackDef = {
  id: string; // dashboard action is `attack.<id>`; result.attack is id with - for _
  n: number;
  name: string;
  attacker: string;
  hint: string;
  command: (security: string) => string;
};

export const ATTACKS: AttackDef[] = [
  {
    id: "read",
    n: 1,
    name: "Broker reads payloads",
    attacker: "Malicious broker",
    hint: "The broker operator dumps every message passing through.",
    command: () => "bbiot attack read",
  },
  {
    id: "modify",
    n: 2,
    name: "Modify thermostat setpoint",
    attacker: "Malicious broker",
    hint: "Phone asks for 21°C, the broker rewrites it to 30°C in flight.",
    command: () => "bbiot attack modify --setpoint 30",
  },
  {
    id: "replay",
    n: 3,
    name: "Replay 'unlock front door'",
    attacker: "Malicious broker",
    hint: "Re-sends a captured unlock command later.",
    command: () => "bbiot attack replay",
  },
  {
    id: "redirect",
    n: 4,
    name: "Redirect unlock to back door",
    attacker: "Malicious broker",
    hint: "Moves a front-door unlock onto the back door's topic.",
    command: () => "bbiot attack redirect --from home/door/front/cmd --to home/door/back/cmd",
  },
  {
    id: "drop",
    n: 5,
    name: "Silently drop the smoke alarm",
    attacker: "Malicious broker",
    hint: "Discards the alarm; can it be noticed?",
    command: () => "bbiot attack drop --topic home/smoke/kitchen",
  },
  {
    id: "mitm_dh",
    n: 6,
    name: "MITM the key exchange",
    attacker: "Malicious broker",
    hint: "Unsigned DH: the broker steals the group key. Signed DH: caught.",
    command: (security) => `bbiot attack mitm-dh${security === "off" ? " --unsigned" : ""}`,
  },
  {
    id: "compromised_device",
    n: 7,
    name: "Compromised thermostat",
    attacker: "Compromised device",
    hint: "Subscribes to door topics → quarantine + rekey; can't read new traffic.",
    command: () => "bbiot attack compromised-device --device thermostat",
  },
  {
    id: "counterfeit",
    n: 8,
    name: "Counterfeit device joins",
    attacker: "Counterfeit device",
    hint: "No root-signed certificate: refused at TLS, hub, door and KDC.",
    command: () => "bbiot attack counterfeit",
  },
  {
    id: "swap_key",
    n: 9,
    name: "Directory swaps a public key",
    attacker: "Compromised directory",
    hint: "Serves a forged key — root signature, log and pin catch it.",
    command: () => "bbiot attack swap-key --device thermostat",
  },
  {
    id: "kdc_vs_directory",
    n: 10,
    name: "Compromised KDC vs. directory",
    attacker: "Compromised KDC / directory",
    hint: "Centralized: the KDC leaks the group key. Decentralized: nothing to leak.",
    command: () => "bbiot attack kdc-vs-directory",
  },
];

export const resultKey = (id: string) => id.replace(/_/g, "-");

export const outcomeTone = { SUCCEEDED: "bad", BLOCKED: "ok", DETECTED: "warn" } as const;
export const outcomeLabel = { SUCCEEDED: "Succeeded", BLOCKED: "Blocked", DETECTED: "Detected" } as const;
