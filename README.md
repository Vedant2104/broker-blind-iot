# broker-blind-iot

A smart-home system where devices talk over MQTT and **the broker and the key
directory are both untrusted**. Even if either is compromised, an attacker
cannot read, forge, replay, redirect, or silently drop device messages. Each
attack is shown live (security off vs. on), every action is a `bbiot` CLI
command, and the overhead is measured.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Scaffold: layout, compose, Mosquitto mTLS, `bbiot` CLI skeleton, tests | ✅ done |
| 1 | Baseline devices, evil-broker proxy, attacks 1–5 succeed, Live Home | ✅ done |
| 2 | Offline root, device certs, 2-of-3 admins, directory, transparency log | ✅ done |
| 3 | securelib AEAD + topic/seq/time/epoch binding, replay window | next |
| 4 | Centralized group keys (KDC) | |
| 5 | Decentralized group keys (MLS via OpenMLS sidecar) | |
| 6 | Hub, heartbeats, acks, MUD policy, quarantine | |
| 7 | Full dashboard | |
| 8 | Benchmarks | |
| 9 | Polish | |

## Architecture (phase 2)

```
 devices ──mTLS──> evil-broker :8883 ──mTLS──> Mosquitto (stock)           host :8884
    │              control API :8090 (arms attacks)
    └──HTTPS──> key directory :8443 ──HTTPS──> transparency log :8444
                (public certs only)            (RFC 6962 Merkle tree)

 offline/  root key + admin keys A/B/C — used only by the one-shot ceremony
           containers (pki-init, commission) and the admin's host CLI
 dashboard :8000 — Mosquitto feed, device feed, trust status
```

- **evil-broker** is the malicious broker operator. It terminates client TLS with
  the broker's own certificate and forwards to Mosquitto. Unarmed, it is a
  transparent pass-through. Armed it modifies, redirects, drops and replays.
- **Devices** each run in their own container with a localhost-only **simulator
  control API**. `bbiot send` and the dashboard ask the *device* to send.
- **Message layer** (`securelib/channel.py`): still `mode=off` (plaintext) until
  phase 3, so attacks 1–5 still succeed.

### Identity and PKI

| Piece | What it does |
|---|---|
| Device keys | Each device generates Ed25519 (signing) + X25519 (key agreement) on first start, in its own key folder. Only a CSR leaves the device. |
| Device certificate | X.509 v3 over the Ed25519 key; X25519 key in a private non-critical extension (OID under `2.25`); custom EKU marks it as a device cert. Signed by the offline Ed25519 root. |
| Offline root | `offline/root.key`. Signs only when an add-device action carries valid signatures from **2 of 3 admins** and the CSR matches the approved hash. |
| Admins A/B/C | Ed25519 keys; their roster is signed by the root. Approvals are signatures over a domain-separated action digest. |
| Key directory | `device_id → certificate`. Untrusted, holds no secrets. Also a bulletin board for pending admin actions. Logs every cert it publishes. |
| Transparency log | Append-only RFC 6962 tree; signed tree heads (log key certified by the root); inclusion and consistency proofs. |
| Peer check (every device) | root signature ✓ → STH signature ✓ → consistent with last STH seen ✓ → inclusion proof ✓ → key pin from first sight ✓. Any failure raises an alert. |

## Layout

```
securelib/   shared device library (core of the project)
cli/         the `bbiot` CLI; cli/actions.py is shared with the dashboard
devices/     simulated locks, thermostat, smoke sensor, phone
evilbroker/  MQTT man-in-the-middle proxy that implements broker attacks
hub/         MUD policy, heartbeats/acks, alerts, quarantine          (phase 6)
directory/   key directory (public certs only) + admin action board
translog/    RFC 6962 Merkle tree (merkle.py) + log service
rootca/      offline root CA (root.py) + 2-of-3 admin approvals (approvals.py)
dashboard/   FastAPI backend (app.py) + React frontend (web/)
bench/       benchmarks, CSVs, charts                                  (phase 8)
broker/      Mosquitto config (stock, mTLS only)
config/      home.yaml: the fixed device and topic list
tests/       pytest suite
secrets/     generated keys and certs (git-ignored)
offline/     offline root + admin keys (git-ignored, never mounted into the system)
```

## Quick start

Requirements: Docker (with Compose v2), [uv](https://docs.astral.sh/uv/), Python 3.11+.
Node 18+ only if you want to run the frontend dev server.

```sh
docker compose up -d --build     # TLS + offline PKI ceremony, broker, evil broker, directory,
                                 # transparency log, 6 devices, dashboard; commissions 5
uv sync --extra dev              # local Python env for the CLI
uv run bbiot doctor              # ✓ mTLS round trip, ✓ no-cert client refused
uv run bbiot status              # every device's state
uv run bbiot log verify          # STH ✓, consistency ✓, every directory cert included ✓
```

Dashboard: <http://localhost:8000> (Live Home).

### Demo: pairing a new device (2 of 3 admins)

`garage-lock` starts uncommissioned (badge "Unverified" with its pairing code).

```sh
uv run bbiot pair --device garage-lock                  # verify CSR, compare codes, post action
uv run bbiot admin approve --admin A --action <id>      # 1/2
uv run bbiot admin approve --admin C --action <id>      # 2/2 → root signs → directory → log
uv run bbiot admin list                                 # the action board
uv run bbiot keys                                       # what the directory serves
uv run bbiot root issue --action <id>                   # refused with fewer than 2 approvals
```

### Demo: the five broker attacks (security OFF)

```sh
uv run bbiot spy                                          # what the broker sees (Ctrl+C)
uv run bbiot send --device phone --topic home/door/front/cmd --cmd unlock
uv run bbiot attack read                                  # 1. broker reads payloads
uv run bbiot attack modify --setpoint 30                  # 2. phone asks 21°C, thermostat gets 30°C
uv run bbiot attack replay                                # 3. captured unlock replayed
uv run bbiot attack replay --seq 3                        #    ...or a specific captured seq
uv run bbiot attack redirect --from home/door/front/cmd --to home/door/back/cmd   # 4.
uv run bbiot attack drop --topic home/smoke/kitchen       # 5. smoke alarm silently dropped
uv run bbiot demo reset                                   # clear rules, reset devices
```

Each prints the attacker's steps and a result line, e.g.

```
[attacker] armed: rewrite setpoint on home/thermostat/living/cmd to 30
[phone] → sent {"cmd": "set", "setpoint": 21.0} to home/thermostat/living/cmd
[attacker] ☠ RESULT: SUCCEEDED — phone asked for 21°C, thermostat accepted 30°C
```

The same attacks are buttons on the dashboard; each shows the exact `bbiot`
command it ran. Container logs show the other side:
`docker compose logs -f evil-broker front-door`.

### Standard tools against the broker

```sh
docker compose run --rm mqtt-tools mosquitto_sub -h broker -p 8883 \
  --cafile /certs/cli/ca.crt --cert /certs/cli/cert.pem --key /certs/cli/key.pem \
  -t 'home/#' -v

docker compose run --rm mqtt-tools mosquitto_pub -h evil-broker -p 8883 \
  --cafile /certs/phone/ca.crt --cert /certs/phone/cert.pem --key /certs/phone/key.pem \
  -t home/door/front/cmd -m '{"from":"phone","seq":1,"cmd":"unlock"}'
```

On Windows Git Bash, prefix these with `MSYS_NO_PATHCONV=1` so `/certs/...` isn't
rewritten to a Windows path.

## Ports (all bound to 127.0.0.1)

| Port | Service |
|---|---|
| 8883 | evil-broker (where every client connects) |
| 8884 | Mosquitto itself |
| 8090 | evil-broker control API |
| 8443 | key directory (HTTPS) |
| 8444 | transparency log (HTTPS) |
| 8101–8106 | device simulator APIs (front-door, back-door, thermostat, smoke-kitchen, phone, garage-lock) |
| 8000 | dashboard |

## Tests

```sh
make test              # unit tests (or: uv run pytest -m "not integration")
make test-integration  # needs the stack up: attacks 1-5, broker, PKI and log checks
make lint
```

On Windows without `make`, run the `uv run ...` lines from the `Makefile`
directly. For integration tests: `docker compose up -d --build`, set
`BBIOT_INTEGRATION=1`, run `uv run pytest -m integration`.

## Frontend development

```sh
cd dashboard/web && npm install && npm run dev    # http://127.0.0.1:5173, proxies to :8000
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BBIOT_CONFIG` | `config/home.yaml` | devices and topics |
| `BBIOT_SECRETS_DIR` | `secrets` | where generated keys/certs go |
| `BBIOT_BROKER_HOST` / `_PORT` | from home.yaml | where clients connect (evil broker) |
| `BBIOT_MOSQUITTO_HOST` / `_PORT` | from home.yaml | Mosquitto itself (spy) |
| `BBIOT_PROXY_HOST` / `_PORT` | from home.yaml | evil-broker control API |
| `BBIOT_DEVICE_HOST` | `127.0.0.1` | device APIs; `service` = use device id as hostname |
| `BBIOT_DIRECTORY_HOST` / `_PORT` | from home.yaml | key directory |
| `BBIOT_TRANSLOG_HOST` / `_PORT` | from home.yaml | transparency log |
| `BBIOT_OFFLINE_DIR` | `offline` | root + admin keys (admin machine only) |

## Dashboard security

The backend only runs a fixed allowlist of actions (`dashboard/app.py: ACTIONS`)
with validated parameters, each mapped to the same function the CLI uses. No
shell execution, no free-text commands. Everything binds to localhost.

## Transport TLS vs. end-to-end

The mTLS set up here protects the network link only — the broker (and the
evil proxy in front of it) still sees plaintext. That is the "security OFF"
baseline. End-to-end protection (securelib, phases 3–6) is what keeps the
broker blind; phase 2 provides the verified identities it is built on.

### Starting over

`docker compose down -v` and deleting `secrets/` and `offline/` gives a fresh
home: the next `docker compose up` re-runs both ceremonies.
