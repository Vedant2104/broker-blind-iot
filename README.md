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
| 2 | Offline root, device certs, 2-of-3 admins, directory, transparency log | next |
| 3 | securelib AEAD + topic/seq/time/epoch binding, replay window | |
| 4 | Centralized group keys (KDC) | |
| 5 | Decentralized group keys (MLS via OpenMLS sidecar) | |
| 6 | Hub, heartbeats, acks, MUD policy, quarantine | |
| 7 | Full dashboard | |
| 8 | Benchmarks | |
| 9 | Polish | |

## Architecture (phase 1)

```
 phone ──────┐                                    ┌───────────────────────┐
 front-door ─┤                                    │  Mosquitto (stock)    │
 back-door ──┼──mTLS──> evil-broker proxy ──mTLS──>  broker:8883          │
 thermostat ─┤          :8883 (host)              │  host: 127.0.0.1:8884 │
 smoke ──────┘          control API :8090         └───────────────────────┘
                        (arms attacks)
 dashboard :8000 ── reads Mosquitto directly ("what the broker sees")
                 └─ polls each device's simulator API ("what the device received")
```

- **evil-broker** is the malicious broker operator. It terminates client TLS with
  the broker's own certificate and forwards to Mosquitto. Unarmed, it is a
  transparent pass-through. Armed (through its control API) it modifies,
  redirects, drops and replays PUBLISH packets.
- **Devices** each run in their own container with a small **simulator control
  API** (localhost only). `bbiot send` and the dashboard ask the *device* to send,
  so in later phases device keys never leave the device.
- **Message layer** (`securelib/channel.py`): in phase 1 only `mode=off` exists —
  plaintext JSON with an unauthenticated `from/seq/ts` envelope.

## Layout

```
securelib/   shared device library (core of the project)
cli/         the `bbiot` CLI; cli/actions.py is shared with the dashboard
devices/     simulated locks, thermostat, smoke sensor, phone
evilbroker/  MQTT man-in-the-middle proxy that implements broker attacks
hub/         MUD policy, heartbeats/acks, alerts, quarantine          (phase 6)
directory/   key directory (public certs only)                         (phase 2)
translog/    Merkle-tree transparency log                              (phase 2)
rootca/      offline root CA + admin approvals                         (phase 2)
dashboard/   FastAPI backend (app.py) + React frontend (web/)
bench/       benchmarks, CSVs, charts                                  (phase 8)
broker/      Mosquitto config (stock, mTLS only)
config/      home.yaml: the fixed device and topic list
tests/       pytest suite
secrets/     generated keys and certs (git-ignored)
```

## Quick start

Requirements: Docker (with Compose v2), [uv](https://docs.astral.sh/uv/), Python 3.11+.
Node 18+ only if you want to run the frontend dev server.

```sh
docker compose up -d --build     # certs, Mosquitto, evil broker, 5 devices, dashboard
uv sync --extra dev              # local Python env for the CLI
uv run bbiot doctor              # ✓ mTLS round trip, ✓ no-cert client refused
uv run bbiot status              # every device's state
```

Dashboard: <http://localhost:8000> (Live Home).

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
  --cafile /certs/ca.crt --cert /certs/clients/cli.crt --key /certs/clients/cli.key \
  -t 'home/#' -v

docker compose run --rm mqtt-tools mosquitto_pub -h evil-broker -p 8883 \
  --cafile /certs/ca.crt --cert /certs/clients/phone.crt --key /certs/clients/phone.key \
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
| 8101–8105 | device simulator APIs (front-door, back-door, thermostat, smoke-kitchen, phone) |
| 8000 | dashboard |

## Tests

```sh
make test              # unit tests (or: uv run pytest -m "not integration")
make test-integration  # needs the stack up; runs attacks 1-5 and broker checks
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

## Dashboard security

The backend only runs a fixed allowlist of actions (`dashboard/app.py: ACTIONS`)
with validated parameters, each mapped to the same function the CLI uses. No
shell execution, no free-text commands. Everything binds to localhost.

## Transport TLS vs. end-to-end

The mTLS set up here protects the network link only — the broker (and the
evil proxy in front of it) still sees plaintext. That is the "security OFF"
baseline. End-to-end protection (securelib, phases 2–6) is what keeps the
broker blind.
