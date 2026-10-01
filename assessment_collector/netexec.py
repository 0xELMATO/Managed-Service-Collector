from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .utils import find_tool


class NetExecCollector:
    def __init__(self, output: Path, redactor: Redactor) -> None:
        self.output, self.redactor = output, redactor
        self.logger = logging.getLogger("netexec")

    def build_command(self, executable: str, target: str, credentials: Credentials) -> list[str]:
        command = [executable, "smb", target, "-u", credentials.username, "-p", credentials.password]
        if credentials.domain:
            command += ["-d", credentials.domain]
        return command

    def collect(self, target: str, credentials: Credentials) -> ModuleResult:
        executable = find_tool("nxc", "netexec")
        if not executable:
            return ModuleResult(False, "NetExec not found; install the Kali 'netexec' package")
        self.output.mkdir(parents=True, exist_ok=True)
        command = self.build_command(executable, target, credentials)
        try:
            completed = subprocess.run(command, cwd=self.output, capture_output=True, text=True,
                                       errors="replace", timeout=1800, shell=False, stdin=subprocess.DEVNULL)
            cleaned = self.redactor.redact(completed.stdout + completed.stderr)
            text_path = self.output / "smb_sweep.txt"
            text_path.write_text(cleaned, encoding="utf-8")
            help_text = subprocess.run([executable, "smb", "--help"], capture_output=True,
                                       text=True, timeout=15).stdout
            details: dict[str, object] = {"tool": executable, "native_json_supported": "--json" in help_text}
            files = [text_path]
            if "--json" not in help_text:
                print("[!] JSON output is not supported by this NetExec version")
                print("[+] Raw output saved to smb_sweep.txt")
            else:
                # Preserve a machine-readable record without re-running authentication.
                json_path = self.output / "smb_sweep.json"
                json_path.write_text(json.dumps({"raw_output": cleaned.splitlines()}, indent=2) + "\n")
                files.append(json_path)
            return ModuleResult(completed.returncode == 0,
                                "" if completed.returncode == 0 else f"NetExec exited {completed.returncode}",
                                {"target": target}, details, files)
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error("NetExec failed: %s", exc)
            return ModuleResult(False, str(exc), {"target": target})
