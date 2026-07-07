"""Centralized logging configuration for ATLAS-Atomic."""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure_logging(level: int | str = logging.INFO) -> None:
    """Configure root logging once. Safe to call repeatedly."""

    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger("atlas_atomic").setLevel(level)
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root = logging.getLogger("atlas_atomic")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger under the ``atlas_atomic`` root."""

    return logging.getLogger(f"atlas_atomic.{name}")
