from __future__ import annotations

import json
import logging
import shutil
import subprocess
import re
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .utils import find_tool


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SIGNING_DISABLED = re.compile(r"\bsigning\s*:\s*(?:false|disabled|no)\b", re.IGNORECASE)


def filter_signing_disabled(output: str) -> str:
    """Return only NetExec host result lines that report SMB signing disabled."""
    matches = []
    for line in output.splitlines():
        clean_line = ANSI_ESCAPE.sub("", line)
        if SIGNING_DISABLED.search(clean_line):
            matches.append(clean_line)
    return "\n".join(matches) + ("\n" if matches else "")


class NetExecCollector:
    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("netexec")

    def build_command(self, executable: str, scope_file: Path, credentials: Credentials) -> list[str]:
        command = [executable, "smb", str(scope_file), "-u", credentials.username, "-p", credentials.password]
        if credentials.domain:
            command += ["-d", credentials.domain]
        return command

    def collect(self, scope_file: Path, credentials: Credentials) -> ModuleResult:
        executable = find_tool("nxc", "netexec")
        if not executable:
            return ModuleResult(False, "NetExec not found; install the Kali 'netexec' package")
        scope_file = scope_file.expanduser().resolve()
        if not scope_file.is_file():
            return ModuleResult(False, f"Scope file not found: {scope_file}")
        if scope_file.stat().st_size == 0:
            return ModuleResult(False, f"Scope file is empty: {scope_file}")
        self.output.mkdir(parents=True, exist_ok=True)
        saved_scope = self.output / "scope.txt"
        shutil.copyfile(scope_file, saved_scope)
        saved_scope.chmod(0o600)
        command = self.build_command(executable, saved_scope, credentials)
        try:
            completed = subprocess.run(command, cwd=self.output, capture_output=True, text=True,
                                       errors="replace", timeout=1800, shell=False, stdin=subprocess.DEVNULL)
            cleaned = self.redactor.redact(completed.stdout + completed.stderr)
            unsigned_only = filter_signing_disabled(cleaned)
            text_path = self.output / "smb_sweep.txt"
            text_path.write_text(unsigned_only, encoding="utf-8")
            print(f"[+] SMB hosts with signing disabled: {len(unsigned_only.splitlines())}")
            help_text = subprocess.run([executable, "smb", "--help"], capture_output=True,
                                       text=True, timeout=15).stdout
            details: dict[str, object] = {"tool": executable, "native_json_supported": "--json" in help_text}
            files = [saved_scope, text_path]
            if "--json" not in help_text:
                print("[!] JSON output is not supported by this NetExec version")
                print("[+] Raw output saved to smb_sweep.txt")
            else:
                # Preserve a machine-readable record without re-running authentication.
                json_path = self.output / "smb_sweep.json"
                json_path.write_text(json.dumps({"signing_disabled": unsigned_only.splitlines()}, indent=2) + "\n")
                files.append(json_path)
            return ModuleResult(completed.returncode == 0,
                                "" if completed.returncode == 0 else f"NetExec exited {completed.returncode}",
                                {"scope_file": str(scope_file)}, details, files)
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error("NetExec failed: %s", exc)
            return ModuleResult(False, str(exc), {"scope_file": str(scope_file)})
