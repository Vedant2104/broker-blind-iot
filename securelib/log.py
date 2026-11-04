"""Structured, human-readable log lines: ``[component] message``.

Never pass secrets (private keys, group keys, protected plaintext) to these loggers.
"""

from __future__ import annotations

import contextlib
import itertools
import logging
import sys
import threading
import time
from collections import deque
from typing import Any


class _ComponentFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"[{record.name}] {record.getMessage()}"


class LogTail:
    """The last N log lines of this process, so a control API can serve them to the
    dashboard's Terminal page. Holds exactly what is printed (no secrets are logged)."""

    def __init__(self, maxlen: int = 400) -> None:
        self._lines: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def add(self, line: str) -> None:
        with self._lock:
            self._lines.append({"id": next(self._ids), "ts": round(time.time(), 3), "line": line})

    def after(self, line_id: int, limit: int = 200) -> list[dict[str, Any]]:
        """Lines newer than ``line_id``. A reader ahead of us saw an earlier run of this
        process (ids restart at 1), so it gets everything we have."""
        with self._lock:
            last = self._lines[-1]["id"] if self._lines else 0
            if line_id > last:
                line_id = 0
            return [x for x in self._lines if x["id"] > line_id][-limit:]


TAIL = LogTail()


class _TailHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        with contextlib.suppress(Exception):
            TAIL.add(self.format(record))


class _StdoutHandler(logging.StreamHandler):
    """Writes to whatever sys.stdout is *now* (so redirection and test capture work)."""

    @property  # type: ignore[override]
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, _value) -> None:
        pass


def get_logger(component: str) -> logging.Logger:
    """Return a logger that prints ``[component] ...`` to stdout."""
    logger = logging.getLogger(component)
    # Windows consoles default to cp1252, which can't print ✓ / ✗.
    if (getattr(sys.stdout, "encoding", "") or "").lower() not in ("utf-8", "utf8"):
        with contextlib.suppress(AttributeError, ValueError):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    if not logger.handlers:
        handler = _StdoutHandler()
        handler.setFormatter(_ComponentFormatter())
        logger.addHandler(handler)
        tail = _TailHandler()
        tail.setFormatter(_ComponentFormatter())
        logger.addHandler(tail)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
