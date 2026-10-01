from __future__ import annotations

import logging
from pathlib import Path

from .credentials import Redactor


class RedactingFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s: %(message)s")
        self.redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        return self.redactor.redact(super().format(record))


def configure_logging(root: Path, redactor: Redactor, debug: bool = False) -> logging.Logger:
    logs = root / "logs"
    formatter = RedactingFormatter(redactor)
    for name in ("collection", "nessus", "certipy", "bloodhound", "pingcastle", "netexec"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        handler = logging.FileHandler(logs / f"{name}.log", encoding="utf-8")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    # Also aggregate every module record into the main collection log.
    aggregate = logging.FileHandler(logs / "collection.log", encoding="utf-8")
    aggregate.setFormatter(formatter)
    for name in ("nessus", "certipy", "bloodhound", "pingcastle", "netexec"):
        logging.getLogger(name).addHandler(aggregate)
    return logging.getLogger("collection")
