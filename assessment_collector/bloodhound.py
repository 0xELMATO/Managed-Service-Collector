from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .process import run_captured
from .utils import find_tool


class BloodHoundCollector:
    TOOLS = ("bloodhound-python", "bloodhound-ce-python")

    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("bloodhound")

    def build_command(self, executable: str, help_text: str, credentials: Credentials,
                      dc: str, method: str, name_server: str = "") -> list[str]:
        required = ("-u", "-p", "-d", "-c")
        if not all(flag in help_text for flag in required):
            raise RuntimeError("Collector help does not expose the expected BloodHound Python interface")
        command = [executable, "-u", credentials.username, "-p", credentials.password,
                   "-d", credentials.domain, "-c", method, "--zip"]
        if "-dc" not in help_text:
            raise RuntimeError("Collector help does not expose the -dc domain-controller option")
        command += ["-dc", dc]
        if name_server:
            if "-ns" not in help_text:
                raise RuntimeError("Installed collector does not support the requested -ns name server option")
            command += ["-ns", name_server]
        return command

    def collect(self, credentials: Credentials, dc: str, method: str = "All",
                name_server: str = "") -> ModuleResult:
        executable = find_tool(*self.TOOLS)
        if not executable:
            return ModuleResult(False, "No BloodHound Python collector found; install 'bloodhound.py'")
        self.output.mkdir(parents=True, exist_ok=True)
        try:
            help_result = subprocess.run([executable, "--help"], capture_output=True, text=True, timeout=15)
            command = self.build_command(executable, help_result.stdout + help_result.stderr,
                                         credentials, dc, method, name_server)
            completed = run_captured(command, self.output, self.redactor, self.logger)
            files = [p for p in self.output.iterdir() if p.is_file()]
            return ModuleResult(completed.returncode == 0,
                                "" if completed.returncode == 0 else f"Collector exited {completed.returncode}",
                                {"domain_controller": dc, "name_server": name_server},
                                {"method": method, "tool": executable}, files)
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            return ModuleResult(False, str(exc), {"domain_controller": dc, "name_server": name_server})
