from __future__ import annotations

import base64
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from .credentials import Redactor
from .models import Credentials, ModuleResult
from .utils import sanitize_filename, unique_path


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class PingCastleCollector:
    """Run a PingCastle health check exclusively over a pywinrm session."""

    def __init__(self, output: Path, host: str, port: int, credentials: Credentials,
                 transport: str = "ntlm", verify_tls: bool = True, path: str = "",
                 redactor: Redactor | None = None) -> None:
        self.output, self.host, self.port = output, host, port
        self.credentials, self.transport, self.verify_tls = credentials, transport, verify_tls
        self.requested_path, self.pingcastle_path = path, ""
        self.redactor = redactor or Redactor([credentials.username, credentials.password])
        self.remote_dir = rf"C:\Windows\Temp\assessment_collector_{uuid.uuid4().hex}"
        self.session: Any = None
        self.logger = logging.getLogger("pingcastle")

    def connect(self) -> None:
        try:
            import winrm
        except ImportError as exc:
            raise RuntimeError("pywinrm not installed; run 'pip install pywinrm'") from exc
        scheme = "https" if self.port == 5986 else "http"
        endpoint = f"{scheme}://{self.host}:{self.port}/wsman"
        validation = "validate" if self.verify_tls else "ignore"
        self.session = winrm.Session(endpoint, auth=(self.credentials.principal, self.credentials.password),
                                     transport=self.transport, server_cert_validation=validation,
                                     read_timeout_sec=3600, operation_timeout_sec=3590)
        self.logger.info("WinRM session configured for %s:%d using %s", self.host, self.port, self.transport)

    def _run(self, script: str, acceptable: tuple[int, ...] = (0,)) -> Any:
        if self.session is None:
            raise RuntimeError("WinRM session is not connected")
        response = self.session.run_ps(script)
        if response.status_code not in acceptable:
            error = response.std_err.decode("utf-8", "replace").strip()
            raise RuntimeError(f"Remote PowerShell failed ({response.status_code}): {error}")
        return response

    def test_connection(self) -> tuple[str, str]:
        response = self._run("$h=$env:COMPUTERNAME; $v=$PSVersionTable.PSVersion.ToString(); Write-Output \"$h`n$v\"")
        lines = response.std_out.decode("utf-8", "replace").strip().splitlines()
        if len(lines) < 2:
            raise RuntimeError("WinRM connectivity test returned an unexpected response")
        self.logger.info("Connected to remote host %s; PowerShell %s", lines[0], lines[1])
        return lines[0], lines[1]

    def find_pingcastle(self) -> str:
        candidates = ([self.requested_path] if self.requested_path else []) + [
            r"C:\Tools\PingCastle\PingCastle.exe", r"C:\PingCastle\PingCastle.exe",
            r"C:\Program Files\PingCastle\PingCastle.exe",
        ]
        literal = ",".join(_ps_quote(value) for value in candidates if value)
        script = (f"$c=@({literal}); $found=$c | Where-Object {{Test-Path -LiteralPath $_ -PathType Leaf}} "
                  "| Select-Object -First 1; if(-not $found){$cmd=Get-Command PingCastle.exe "
                  "-ErrorAction SilentlyContinue; if($cmd){$found=$cmd.Source}}; if($found){$found}else{exit 2}")
        response = self._run(script)
        self.pingcastle_path = response.std_out.decode("utf-8", "replace").strip()
        if not self.pingcastle_path:
            raise RuntimeError("PingCastle.exe was not found in the supplied or standard locations")
        self.logger.info("PingCastle found at %s", self.pingcastle_path)
        return self.pingcastle_path

    def execute_pingcastle(self) -> tuple[int, str, str]:
        exe = _ps_quote(self.pingcastle_path)
        help_response = self._run(f"& {exe} --help", acceptable=tuple(range(256)))
        help_text = (help_response.std_out + help_response.std_err).decode("utf-8", "replace")
        if "--healthcheck" not in help_text:
            raise RuntimeError("Installed PingCastle help does not advertise the read-only --healthcheck mode")
        script = (f"$dir={_ps_quote(self.remote_dir)}; New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null; "
                  f"Push-Location $dir; & {exe} --healthcheck; $code=$LASTEXITCODE; Pop-Location; exit $code")
        response = self._run(script, acceptable=tuple(range(256)))
        stdout = response.std_out.decode("utf-8", "replace")
        stderr = response.std_err.decode("utf-8", "replace")
        execution_log = f"exit_code={response.status_code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        (self.output / "remote_execution.log").write_text(self.redactor.redact(execution_log), encoding="utf-8")
        if response.status_code != 0:
            raise RuntimeError(f"PingCastle exited with code {response.status_code}")
        return response.status_code, stdout, stderr

    def collect_output(self) -> list[Path]:
        listing = self._run(f"Get-ChildItem -LiteralPath {_ps_quote(self.remote_dir)} -File | "
                            "Select-Object Name,Length | ConvertTo-Json -Compress")
        raw = listing.std_out.decode("utf-8", "replace").strip()
        records = json.loads(raw) if raw else []
        if isinstance(records, dict):
            records = [records]
        collected: list[Path] = []
        for record in records:
            name = str(record["Name"])
            size = int(record["Length"])
            local = unique_path(self.output / sanitize_filename(name))
            with local.open("wb") as destination:
                offset = 0
                while offset < size:
                    count = min(384 * 1024, size - offset)
                    remote_file = self.remote_dir + "\\" + name
                    script = (f"$f=[IO.File]::OpenRead({_ps_quote(remote_file)}); try{{$f.Position={offset};"
                              f"$b=New-Object byte[] {count};$n=$f.Read($b,0,$b.Length);"
                              "[Convert]::ToBase64String($b,0,$n)}finally{$f.Dispose()}")
                    response = self._run(script)
                    data = base64.b64decode(response.std_out.strip(), validate=True)
                    if not data:
                        raise RuntimeError(f"Transfer stalled while retrieving {name}")
                    destination.write(data)
                    offset += len(data)
            if local.stat().st_size != size:
                raise RuntimeError(f"Size mismatch retrieving {name}")
            collected.append(local)
            self.logger.info("Retrieved %s (%d bytes)", name, size)
        if not collected:
            raise RuntimeError("PingCastle completed but generated no output files")
        return collected

    def cleanup(self) -> None:
        if self.session is not None:
            self._run(f"if(Test-Path -LiteralPath {_ps_quote(self.remote_dir)}){{Remove-Item -LiteralPath "
                      f"{_ps_quote(self.remote_dir)} -Recurse -Force}}")

    def disconnect(self) -> None:
        self.session = None

    def collect(self) -> ModuleResult:
        self.output.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        try:
            self.connect()
            remote_host, version = self.test_connection()
            print(f"[+] WinRM connection successful\n[+] Remote host: {remote_host}\n[+] PowerShell version: {version}")
            self.find_pingcastle()
            print(f"[+] PingCastle found: {self.pingcastle_path}\n[+] Starting PingCastle\n[*] Waiting for PingCastle to complete...")
            self.execute_pingcastle()
            files = self.collect_output()
            files.append(self.output / "remote_execution.log")
            self.cleanup()
            print("[+] PingCastle completed successfully")
            return ModuleResult(True, targets={"host": self.host, "port": str(self.port)},
                                details={"transport": self.transport, "path": self.pingcastle_path}, files=files)
        except Exception as exc:
            self.logger.error("PingCastle collection failed: %s", exc)
            return ModuleResult(False, str(exc), {"host": self.host, "port": str(self.port)}, files=files)
        finally:
            self.disconnect()
