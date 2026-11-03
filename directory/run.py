"""Run the key directory over HTTPS."""

from __future__ import annotations

import json
import os
from pathlib import Path

import uvicorn

from directory.service import DirectoryStore, create_app
from rootca.approvals import verify_roster
from securelib.config import Config
from securelib.log import get_logger
from securelib.pki import load_root
from securelib.services import LogClient
from securelib.tls import client_paths
from translog.run import wait_for

log = get_logger("directory")


def serve(cfg: Config) -> None:
    public = cfg.pki_public_dir
    wait_for(public / "root.crt", "the root certificate")
    wait_for(public / "admins.json", "the admin roster")
    root_pem = (public / "root.crt").read_bytes()
    _, root_key = load_root(root_pem)
    roster = verify_roster(json.loads((public / "admins.json").read_text("utf-8")), root_key)

    log_client = LogClient.connect(cfg, "directory")
    data = Path(os.environ.get("BBIOT_DATA_DIR", "data")) / "directory" / "store.json"
    store = DirectoryStore(data)
    tls = client_paths(cfg.tls_dir, "directory")
    host = os.environ.get("BBIOT_LISTEN", "127.0.0.1")
    log.info(
        f"serving on https://{host}:{cfg.directory_port}, "
        f"{len(store.data['certs'])} certificates; holds no private keys"
    )
    uvicorn.run(
        create_app(store, root_pem, roster, log_client.add),
        host=host,
        port=cfg.directory_port,
        ssl_certfile=str(tls.cert),
        ssl_keyfile=str(tls.key),
        log_level="warning",
    )
