"""
NexIDS Logger
=============
Centralised logging utility for all NexIDS modules.

Provides a pre-configured logger with coloured console output and
an optional rotating file handler so that every subsystem can call
``get_logger(__name__)`` and get a consistent experience.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# ---------------------------------------------------------------------------
# Colour map for log levels
# ---------------------------------------------------------------------------
_LEVEL_COLOURS: dict[int, str] = {
    logging.DEBUG:    Fore.CYAN,
    logging.INFO:     Fore.GREEN,
    logging.WARNING:  Fore.YELLOW,
    logging.ERROR:    Fore.RED,
    logging.CRITICAL: Fore.MAGENTA,
}

LOG_DIR = Path(__file__).resolve().parents[2] / "logs"


class _ColouredFormatter(logging.Formatter):
    """Formatter that prepends ANSI colour codes to the level name."""

    _FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    _DATE_FMT = "%Y-%m-%d %H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        colour = _LEVEL_COLOURS.get(record.levelno, "")
        record.levelname = f"{colour}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

    def __init__(self) -> None:
        super().__init__(fmt=self._FMT, datefmt=self._DATE_FMT)


class _PlainFormatter(logging.Formatter):
    """Plain (no colour) formatter for file output."""

    _FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    _DATE_FMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self) -> None:
        super().__init__(fmt=self._FMT, datefmt=self._DATE_FMT)


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """Return a named logger that writes to both console and a rotating file.

    Parameters
    ----------
    name:
        Logger name — typically ``__name__`` of the calling module.
    level:
        Minimum log level.  Defaults to ``DEBUG``.

    Returns
    -------
    logging.Logger
        A fully configured logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # --- Console handler ---
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(_ColouredFormatter())
    logger.addHandler(ch)

    # --- Rotating file handler ---
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / "nexids.log"
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,   # 5 MB per file
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(level)
        fh.setFormatter(_PlainFormatter())
        logger.addHandler(fh)
    except OSError as exc:
        logger.warning("Could not open log file: %s", exc)

    # Don't propagate to root — avoids duplicate output
    logger.propagate = False

    return logger
