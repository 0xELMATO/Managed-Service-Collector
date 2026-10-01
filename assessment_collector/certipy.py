from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .process import run_captured
from .utils import find_tool


class CertipyCollector:
    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("certipy")

    def build_command(self, executable: str, help_text: str, credentials: Credentials,
                      target: str) -> list[str]:
        if "find" not in help_text.lower():
            raise RuntimeError("Installed Certipy does not advertise the read-only 'find' command")
        prefix = str(self.output / "certipy")
        command = [executable, "find", "-u", f"{credentials.username}@{credentials.domain}",
                   "-p", credentials.password, "-dc-ip", target, "-output", prefix]
        find_help = subprocess.run([executable, "find", "-h"], capture_output=True, text=True,
                                   timeout=15).stdout
        if "-json" in find_help:
            command.append("-json")
        if "-text" in find_help:
            command.append("-text")
        return command

    def collect(self, credentials: Credentials, target: str) -> ModuleResult:
        executable = find_tool("certipy", "certipy-ad")
        if not executable:
            return ModuleResult(False, "Certipy not found; install with 'sudo apt install certipy-ad'")
        self.output.mkdir(parents=True, exist_ok=True)
        try:
            help_result = subprocess.run([executable, "--help"], capture_output=True, text=True, timeout=15)
            command = self.build_command(executable, help_result.stdout + help_result.stderr, credentials, target)
            completed = run_captured(command, self.output, self.redactor, self.logger)
            files = [p for p in self.output.iterdir() if p.is_file()]
            return ModuleResult(completed.returncode == 0,
                                "" if completed.returncode == 0 else f"Certipy exited {completed.returncode}",
                                {"domain_controller": target}, {"tool": executable}, files)
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            self.logger.error("Certipy failed: %s", exc)
            return ModuleResult(False, str(exc), {"domain_controller": target})
