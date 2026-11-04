# Demo script (about 15 minutes)

A walk-through for presenting Broker-Blind IoT live. Each step says what to **click**
on the dashboard (http://localhost:8000), the **same command** if you prefer a
terminal, what to **say**, and what the audience should **see**.

The story: first show that TLS alone does not protect you from the broker
(security OFF), then switch on end-to-end protection and replay the same attacks
(security ON), then attack the keys, then insiders, then compare the two group-key
modes, and finish with the cost.

---

## Before the audience arrives (5 minutes)

```sh
docker compose up -d --build     # first time takes a few minutes
uv run bbiot doctor              # every line ✓, ends with "ready for the demo"
uv run bbiot demo start          # reset + security OFF + centralized keys
```

- Open the dashboard full screen on the projector. Check the top bar: all status
  pills green, **OFF** and **Centralized** selected.
- Optional: `scripts/demo-tmux.sh` (Linux/macOS/WSL) in a second window, or use the
  dashboard's **Terminal** page — same panes.
- Have `docs/architecture.png` ready for the intro.

If `bbiot doctor` shows ✗, see **If something goes wrong** at the end.

---

## 1. The setup (1 minute)

**Show** the architecture diagram.

**Say:** "A smart home: door locks, a thermostat, a smoke sensor and a phone app talk
over MQTT. The broker in the middle is run by someone we don't trust — here it's this
*evil-broker proxy* in front of a stock Mosquitto. The key directory is untrusted too.
Everything uses TLS. Let's see whether that's enough."

---

## 2. Security OFF: TLS is not enough (4 minutes)

**Live Home page.** Point at the three columns: devices, *what the broker sees* vs.
*what the devices received*, alerts.

| # | Click | Or type | Say / see |
|---|---|---|---|
| — | Phone card → **Unlock Front Door**, then **Lock Front Door** | `bbiot send --device phone --topic home/door/front/cmd --cmd unlock` | The broker column shows the command **in plain text** — TLS only protects each hop. |
| 1 | **Attack Console** → card 1 **Launch** | `bbiot attack read` | **Succeeded**: the broker read every payload. |
| 2 | card 2 **Launch** | `bbiot attack modify --setpoint 30` | Phone asked for 21 °C, the thermostat accepted **30 °C**. |
| 3 | card 3 **Launch** | `bbiot attack replay` | A captured "unlock" is sent again — the front door **unlocks**. |
| 4 | card 4 **Launch** | `bbiot attack redirect --from home/door/front/cmd --to home/door/back/cmd` | An unlock meant for the front door opens the **back door**. |
| 5 | card 5 **Launch** | `bbiot attack drop --topic home/smoke/kitchen` | The smoke alarm vanishes and **nobody notices**. |

Each card shows the exact command and its output — **Copy** pastes it into a terminal
with identical results. The results table at the bottom fills in the *OFF ·
Centralized* column in red.

---

## 3. Security ON: the broker goes blind (4 minutes)

**Click** the top bar **ON** (or `bbiot security on`). Wait until the toggle shows ON
(a few seconds; devices switch one by one).

**Say:** "Now every message is sealed end to end: AES-GCM with the topic, sender,
sequence number, timestamp and key epoch bound into it, and commands are signed.
Same attacks, same broker."

| # | Launch | Expected result (card + *What the device received*) |
|---|---|---|
| 1 | read | **Blocked** — "all payloads were ciphertext". Live Home's broker column now shows hex. |
| 2 | modify | **Blocked** — the thermostat rejects the altered message: *tag invalid* (or *wrong epoch* right after a rekey). |
| 3 | replay | **Blocked** — front door: *replay (seq N already seen, window …)*. |
| 4 | redirect | **Blocked** — back door: *wrong topic (sealed for another topic)*. |
| 5 | drop | **Detected** — the broker can always drop, but the hub raises **DROPPED** within a few seconds (sequence gap). |

**Say for 5:** "We can't stop a broker from dropping messages — nobody can — but we
detect it: sequence gaps, missing heartbeats and missing end-to-end acks."

---

## 4. Attacks on the keys (2 minutes)

| # | Do | Expected |
|---|---|---|
| 6 | Attack 6 with **OFF** first (it uses an unsigned key exchange): **Succeeded**, the broker stole the group key. Then **ON**: **Blocked** — *KDC signature invalid (MITM?)*. | Why the key exchange must be signed. |
| 9 | **Keys & Trust** page, then Attack Console card 9 (`bbiot attack swap-key --device thermostat`). | **Blocked**: *certificate signature does not verify against the root*. Back on Keys & Trust: a red **"Key directory mismatch detected"** banner. |
| — | **Verify log** (top bar) or `bbiot log verify` | Tree head signed, history consistent, every certificate included and pinned. |

**Say:** "The directory can lie, but every key must be signed by our offline root,
appear in the append-only transparency log, and match the key we pinned the first
time we saw it."

---

## 5. Insiders: a hacked device and a fake one (2 minutes)

| # | Do | Expected |
|---|---|---|
| 7 | Attack 7 (`bbiot attack compromised-device --device thermostat`) | **Blocked**: the hub sees the thermostat subscribe to door commands (not in its MUD profile), quarantines it, the group rekeys — the thermostat **can't decrypt anything new**. |
| 8 | **Pairing** page → **Counterfeit device tries to join** (`bbiot attack counterfeit`) | Step 2 turns **red**: no root-signed certificate; refused at TLS, hub, door and KDC. |
| — | **Pairing** → **Start pairing** for garage-lock (if it is already paired: **Revoke** it first and approve as two admins) → **Codes match** → **Admin A** → **Admin B** | 2-of-3 admin signatures, the offline root issues the certificate, it's logged, the device joins and the group **rekeys**. |

**Say:** "Adding or removing a device needs two of three admins. One stolen admin key
isn't enough."

---

## 6. Who can read everything? Centralized vs. decentralized (1 minute)

| # | Do | Expected |
|---|---|---|
| 10 | **Centralized**: attack 10 (`bbiot attack kdc-vs-directory`) | **Succeeded**: a compromised KDC knows the group key and decrypts traffic. |
| 10 | Top bar **Decentralized** (`bbiot keymode decentralized`), wait for the epoch badge to say MLS, run attack 10 again | **Blocked**: with MLS the devices derive the key themselves; the directory only stores public key packages — nothing to leak. |
| — | **Keys & Trust** → group card | The MLS ratchet tree, the committer's path in green. |

---

## 7. What does it cost? (1 minute)

**Benchmarks** page (optionally **Run quick benchmark**, ~10 s):

- About **+0.1 ms** and **+41 B** (state update) / **+105 B** (signed command) per message.
- Rekeying 1000 devices: KDC ~7 ms but 1000 messages; MLS ~42 ms and a single commit.
- A dropped alarm is noticed in a few seconds.

Finish on **Attack Console → results table**: red column for OFF, green/amber for ON.

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| A status pill is red | `docker compose ps`; `docker compose up -d` restarts what stopped. |
| Toggle shows neither side / "mixed" | Devices are still switching — wait 5 s. Still mixed: click the mode again. |
| An attack card says "another action is still running" | Wait for the previous one to finish (each takes a few seconds). |
| A door stays unlocked / a device stays quarantined | **Reset demo** (top bar) or `bbiot demo reset`. |
| Pairing says "already commissioned" | Click **Revoke garage-lock**, approve as two admins, then pair again. |
| Approve buttons are disabled | Admin console offline: `docker compose up -d admin-console`, or approve from a terminal with `bbiot admin approve --admin A --action <id>`. |
| An admin action shows "expired" | Actions expire after 60 minutes; start the pairing again. |
| Anything else | `bbiot demo start` returns to the opening state; `bbiot doctor` says what's wrong. |
