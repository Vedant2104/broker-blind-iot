"""Structured, human-readable log lines: ``[component] message``.

Never pass secrets (private keys, group keys, protected plaintext) to these loggers.
"""

from __future__ import annotations

import contextlib
import logging
import sys


class _ComponentFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"[{record.name}] {record.getMessage()}"


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
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
