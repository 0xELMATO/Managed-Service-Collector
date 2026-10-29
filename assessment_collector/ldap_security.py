from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .utils import find_tool

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LDAP_FINDING = re.compile(r"(?:ldap\s+signing|channel\s+binding)", re.IGNORECASE)


def filter_ldap_security_findings(output: str) -> str:
    """Keep only DC result lines describing LDAP signing or channel binding."""
    findings = []
    for line in output.splitlines():
        clean_line = ANSI_ESCAPE.sub("", line)
        if LDAP_FINDING.search(clean_line):
            findings.append(clean_line)
    return "\n".join(findings) + ("\n" if findings else "")


class LdapSecurityCollector:
    """Check LDAP signing and channel binding with NetExec's read-only ldap-checker."""

    MODULE = "ldap-checker"

    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("ldap")

    def build_command(self, executable: str, scope_file: Path, credentials: Credentials) -> list[str]:
        command = [executable, "ldap", str(scope_file), "-u", credentials.username,
                   "-p", credentials.password]
        if credentials.domain:
            command += ["-d", credentials.domain]
        command += ["-M", self.MODULE]
        return command

    def _module_available(self, executable: str) -> bool:
        result = subprocess.run([executable, "ldap", "-L"], capture_output=True, text=True,
                                errors="replace", timeout=30, shell=False)
        return self.MODULE.casefold() in (result.stdout + result.stderr).casefold()

    def collect(self, scope_file: Path, credentials: Credentials) -> ModuleResult:
        executable = find_tool("nxc", "netexec")
        if not executable:
            return ModuleResult(False, "NetExec not found; install the Kali 'netexec' package")
        scope_file = scope_file.expanduser().resolve()
        if not scope_file.is_file():
            return ModuleResult(False, f"Domain-controller scope file not found: {scope_file}")
        if scope_file.stat().st_size == 0:
            return ModuleResult(False, f"Domain-controller scope file is empty: {scope_file}")
        self.output.mkdir(parents=True, exist_ok=True)
        saved_scope = self.output / "dc_scope.txt"
        shutil.copyfile(scope_file, saved_scope)
        saved_scope.chmod(0o600)
        try:
            if not self._module_available(executable):
                return ModuleResult(
                    False,
                    "Installed NetExec does not provide the ldap-checker module required for LDAP signing/channel binding",
                    {"scope_file": str(scope_file)},
                )
            command = self.build_command(executable, saved_scope, credentials)
            safe_command = " ".join(self.redactor.redact(item) for item in command)
            self.logger.info("Executing: %s", safe_command)
            completed = subprocess.run(command, cwd=self.output, capture_output=True, text=True,
                                       errors="replace", timeout=600, shell=False,
                                       stdin=subprocess.DEVNULL)
            content = filter_ldap_security_findings(
                self.redactor.redact(completed.stdout + completed.stderr))
            report = self.output / "ldap_signing_channel_binding.txt"
            report.write_text(content, encoding="utf-8")
            print(f"[+] LDAP signing/channel-binding findings: {len(content.splitlines())}")
            self.logger.info("NetExec LDAP checker exit code: %d", completed.returncode)
            return ModuleResult(
                completed.returncode == 0,
                "" if completed.returncode == 0 else f"NetExec LDAP checker exited {completed.returncode}",
                {"scope_file": str(scope_file)},
                {"tool": executable, "module": self.MODULE},
                [saved_scope, report],
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error("LDAP security check failed: %s", exc)
            return ModuleResult(False, str(exc), {"scope_file": str(scope_file)})
