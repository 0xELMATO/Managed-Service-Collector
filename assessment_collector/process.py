from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from .credentials import Redactor


def run_captured(argv: list[str], cwd: Path, redactor: Redactor, logger: logging.Logger,
                 timeout: int = 1800, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    safe_command = " ".join(redactor.redact(part) for part in argv)
    logger.info("Executing: %s", safe_command)
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, errors="replace",
                               timeout=timeout, env=env, shell=False, stdin=subprocess.DEVNULL)
    (cwd / "stdout.log").write_text(redactor.redact(completed.stdout), encoding="utf-8")
    (cwd / "stderr.log").write_text(redactor.redact(completed.stderr), encoding="utf-8")
    logger.info("Command exit code: %d", completed.returncode)
    return completed


def private_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env
