from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .utils import find_tool


class LdapSecurityCollector:
    """Check LDAP signing and channel binding with NetExec's read-only ldap-checker."""

    MODULE = "ldap-checker"

    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("ldap")

    def build_command(self, executable: str, target: str, credentials: Credentials) -> list[str]:
        command = [executable, "ldap", target, "-u", credentials.username,
                   "-p", credentials.password]
        if credentials.domain:
            command += ["-d", credentials.domain]
        command += ["-M", self.MODULE]
        return command

    def _module_available(self, executable: str) -> bool:
        result = subprocess.run([executable, "ldap", "-L"], capture_output=True, text=True,
                                errors="replace", timeout=30, shell=False)
        return self.MODULE.casefold() in (result.stdout + result.stderr).casefold()

    def collect(self, target: str, credentials: Credentials) -> ModuleResult:
        executable = find_tool("nxc", "netexec")
        if not executable:
            return ModuleResult(False, "NetExec not found; install the Kali 'netexec' package")
        self.output.mkdir(parents=True, exist_ok=True)
        try:
            if not self._module_available(executable):
                return ModuleResult(
                    False,
                    "Installed NetExec does not provide the ldap-checker module required for LDAP signing/channel binding",
                    {"target": target},
                )
            command = self.build_command(executable, target, credentials)
            safe_command = " ".join(self.redactor.redact(item) for item in command)
            self.logger.info("Executing: %s", safe_command)
            completed = subprocess.run(command, cwd=self.output, capture_output=True, text=True,
                                       errors="replace", timeout=600, shell=False,
                                       stdin=subprocess.DEVNULL)
            content = self.redactor.redact(completed.stdout + completed.stderr)
            report = self.output / "ldap_signing_channel_binding.txt"
            report.write_text(content, encoding="utf-8")
            self.logger.info("NetExec LDAP checker exit code: %d", completed.returncode)
            return ModuleResult(
                completed.returncode == 0,
                "" if completed.returncode == 0 else f"NetExec LDAP checker exited {completed.returncode}",
                {"target": target},
                {"tool": executable, "module": self.MODULE},
                [report],
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error("LDAP security check failed: %s", exc)
            return ModuleResult(False, str(exc), {"target": target})
