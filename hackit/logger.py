"""
Central logger for HackIt tools.
Supports colored console output, file logging, structured JSON logging,
and per-module log levels.
"""
import logging
import os
import sys
import json
from datetime import datetime
from pathlib import Path

LOGS_DIR = Path.home() / ".hackit_logs"

CSI = "\x1b["
RESET = f"{CSI}0m"
LOG_COLORS = {
    logging.DEBUG:    f"{CSI}2m",
    logging.INFO:     f"{CSI}96m",
    logging.WARNING:  f"{CSI}93m",
    logging.ERROR:    f"{CSI}91m",
    logging.CRITICAL: f"{CSI}91;1m",
}
LEVEL_ICONS = {
    logging.DEBUG:    "[-]",
    logging.INFO:     "[+]",
    logging.WARNING:  "[!]",
    logging.ERROR:    "[x]",
    logging.CRITICAL: "[X]",
}


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        color = LOG_COLORS.get(record.levelno, "")
        icon = LEVEL_ICONS.get(record.levelno, "[?]")
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        name = record.name.replace("hackit.", "")
        msg = record.getMessage()
        return f"  {color}{icon} {ts} {name}: {msg}{RESET}"


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class FileFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        return f"{ts} [{record.levelname:>8}] {record.name}: {record.getMessage()}"


_loggers = {}


def get_logger(name: str = 'hackit', level: int = None, file_log: bool = False) -> logging.Logger:
    if name in _loggers:
        logger = _loggers[name]
        if level is not None:
            logger.setLevel(level)
        return logger

    logger = logging.getLogger(name)
    logger.propagate = False

    if not logger.handlers:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(ColoredFormatter())
        logger.addHandler(console)

        if file_log or os.environ.get("HACKIT_FILE_LOG"):
            LOGS_DIR.mkdir(parents=True, exist_ok=True)
            today = datetime.now().strftime("%Y-%m-%d")
            fh = logging.FileHandler(LOGS_DIR / f"hackit_{today}.log", encoding="utf-8")
            fh.setFormatter(FileFormatter())
            logger.addHandler(fh)

    env_level = os.environ.get("HACKIT_LOG_LEVEL", "").upper()
    if level is not None:
        logger.setLevel(level)
    elif env_level and hasattr(logging, env_level):
        logger.setLevel(getattr(logging, env_level))
    else:
        logger.setLevel(logging.INFO)

    _loggers[name] = logger
    return logger


def set_global_level(level: int):
    for lg in _loggers.values():
        lg.setLevel(level)


def enable_file_logging():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    for lg in _loggers.values():
        if not any(isinstance(h, logging.FileHandler) for h in lg.handlers):
            fh = logging.FileHandler(LOGS_DIR / f"hackit_{today}.log", encoding="utf-8")
            fh.setFormatter(FileFormatter())
            lg.addHandler(fh)
