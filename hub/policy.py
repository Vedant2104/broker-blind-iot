"""MUD-style policy profiles (in the spirit of RFC 8520, adapted to MQTT topics).

One JSON profile per identity in config/mud/<id>.json:

  {
    "mud_version": 1,
    "device": "thermostat",
    "systeminfo": "Living room thermostat",
    "publish":   ["home/thermostat/living/state", "hb/thermostat", ...],
    "subscribe": ["home/thermostat/living/cmd", "kdc/key/thermostat", ...],
    "accept_commands_from": ["phone", "hub"]
  }

The hub gateway checks every PUBLISH topic and SUBSCRIBE filter against the
sender's profile; devices check `accept_commands_from` on authenticated commands.
An identity without a profile may do nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securelib.config import Config, Device


def topic_matches(flt: str, topic: str) -> bool:
    """MQTT filter matching ('+' one level, '#' the rest)."""
    f, t = flt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t) or (part != "+" and part != t[i]):
            return False
    return len(f) == len(t)


def filter_covers(allowed: str, requested: str) -> bool:
    """True if every topic matching `requested` also matches `allowed` — so a device
    can't widen an allowed subscription with its own wildcards."""
    a, r = allowed.split("/"), requested.split("/")
    for i, part in enumerate(a):
        if part == "#":
            return True
        if i >= len(r):
            return False
        if r[i] == "#":
            return False  # requested is broader than this level allows
        if part == "+":
            continue
        if r[i] != part:  # literal: requested must be the same literal ('+' is broader)
            return False
    return len(a) == len(r)


class Profile:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.device = data["device"]
        self.publish: list[str] = list(data.get("publish", []))
        self.subscribe: list[str] = list(data.get("subscribe", []))
        self.accept_from: list[str] = list(data.get("accept_commands_from", []))

    def check_publish(self, topic: str) -> str | None:
        if any(topic_matches(p, topic) for p in self.publish):
            return None
        return f"published to {topic} — not in {self.device}'s MUD profile"

    def check_subscribe(self, flt: str) -> str | None:
        if any(filter_covers(p, flt) for p in self.subscribe):
            return None
        return f"subscribed to {flt} — not in {self.device}'s MUD profile"

    def accepts_command_from(self, sender: str) -> bool:
        return sender in self.accept_from


DENY_ALL = Profile({"device": "?", "publish": [], "subscribe": []})


def _common(dev_id: str) -> tuple[list[str], list[str]]:
    publish = [f"hb/{dev_id}", f"ack/{dev_id}", f"kdc/join/{dev_id}", f"mls/rejoin/{dev_id}"]
    subscribe = [
        "kdc/announce",
        f"kdc/session/{dev_id}",
        f"kdc/key/{dev_id}",
        "mls/commit",
        "mls/welcome",
        "hub/quarantine",
    ]
    return publish, subscribe


def default_profile(cfg: Config, ident: str) -> dict[str, Any]:
    """The intended behaviour of each identity, derived from home.yaml."""
    devices = cfg.devices
    cmd_topics = sorted(d.topics["cmd"] for d in devices.values() if "cmd" in d.topics)
    watch_topics = sorted(
        t for d in devices.values() for k, t in d.topics.items() if k in ("state", "alarm")
    )
    profile: dict[str, Any] = {"mud_version": 1, "device": ident}
    dev: Device | None = devices.get(ident)

    if dev is not None:
        publish, subscribe = _common(ident)
        profile["systeminfo"] = dev.label
        if dev.kind == "app":
            publish += cmd_topics
            subscribe += watch_topics + ["ack/+"]
        elif dev.kind == "hub":
            publish += cmd_topics + ["mls/commit", "mls/welcome", "hub/quarantine"]
            subscribe += ["home/#", "hb/+", "ack/+", "mls/rejoin/+"]
        else:
            publish += [t for k, t in dev.topics.items() if k in ("state", "alarm")]
            subscribe += [dev.topics["cmd"]] if "cmd" in dev.topics else []
            if dev.kind == "smoke":
                subscribe.append("ack/hub")  # end-to-end ack for alarms
            profile["accept_commands_from"] = ["phone", "hub"]
        profile["publish"], profile["subscribe"] = publish, subscribe
    elif ident == "kdc":
        profile["systeminfo"] = "Key Distribution Center"
        profile["publish"] = ["kdc/announce", "kdc/session/+", "kdc/key/+"]
        profile["subscribe"] = ["kdc/join/+", "hub/quarantine"]
    elif ident == "cli":
        profile["systeminfo"] = "bbiot CLI (health checks only)"
        profile["publish"] = ["bbiot/selftest/#"]
        profile["subscribe"] = ["bbiot/selftest/#"]
    else:  # dashboard, evil-proxy, counterfeit, ...: nothing through the hub
        profile["publish"], profile["subscribe"] = [], []
    return profile


class PolicyStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.profiles: dict[str, Profile] = {}
        self.reload()

    def reload(self) -> None:
        self.profiles = {}
        for path in sorted(self.directory.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.profiles[data["device"]] = Profile(data)

    def get(self, ident: str) -> Profile:
        return self.profiles.get(ident, DENY_ALL)


def write_profiles(cfg: Config, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for ident in [*cfg.devices, "kdc", "cli", "dashboard", "evil-proxy"]:
        path = directory / f"{ident}.json"
        path.write_text(json.dumps(default_profile(cfg, ident), indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written
