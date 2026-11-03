"""Run the transparency log over HTTPS."""

from __future__ import annotations

import os
import time
from pathlib import Path

import uvicorn

from securelib.config import Config
from securelib.identity import read_private
from securelib.log import get_logger
from securelib.tls import client_paths
from translog.service import LogStore, create_app

log = get_logger("translog")


def wait_for(path: Path, what: str) -> None:
    while not path.is_file():
        log.info(f"waiting for {what} at {path.as_posix()} (run: bbiot pki init)")
        time.sleep(3)


def serve(cfg: Config) -> None:
    root = cfg.pki_public_dir / "root.crt"
    wait_for(cfg.translog_key_path, "the log signing key")
    wait_for(root, "the root certificate")
    data = Path(os.environ.get("BBIOT_DATA_DIR", "data")) / "translog" / "leaves.txt"
    store = LogStore(data, read_private(cfg.translog_key_path))
    tls = client_paths(cfg.tls_dir, "translog")
    host = os.environ.get("BBIOT_LISTEN", "127.0.0.1")
    log.info(f"serving on https://{host}:{cfg.translog_port}, {len(store.hashes)} leaves loaded")
    uvicorn.run(
        create_app(store, root.read_bytes()),
        host=host,
        port=cfg.translog_port,
        ssl_certfile=str(tls.cert),
        ssl_keyfile=str(tls.key),
        log_level="warning",
    )
