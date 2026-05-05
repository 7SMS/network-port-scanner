"""
Logging setup. One file logger + one stderr logger for dev.
GUI plugs in its own handler to display log records in the terminal pane.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(log_dir: Path | None = None,
                  level: int = logging.INFO) -> logging.Logger:
    """Configure root logging once. Idempotent."""
    log_dir = log_dir or (Path.home() / ".portscanner" / "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "scanner.log"

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers on re-entry (e.g. tests)
    if any(getattr(h, "_portscanner_marker", False) for h in root.handlers):
        return root

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3,
                             encoding="utf-8")
    fh.setFormatter(fmt)
    fh._portscanner_marker = True  # type: ignore[attr-defined]
    root.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh._portscanner_marker = True  # type: ignore[attr-defined]
    root.addHandler(sh)

    return root
