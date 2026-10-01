from __future__ import annotations

import logging
import time
import warnings
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

from .models import ModuleResult
from .utils import sanitize_filename, unique_path


class NessusError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ExportSpec:
    label: str
    extension: str
    payload: dict[str, Any]
    postfix: str


EXPORTS = {
    "pdf_host": ExportSpec("PDF by host", ".pdf", {"format": "pdf", "chapters": "vuln_hosts_summary"}, "by_host"),
    "pdf_plugin": ExportSpec("PDF by plugin", ".pdf", {"format": "pdf", "chapters": "vuln_by_plugin"}, "by_plugin"),
    "csv": ExportSpec("CSV", ".csv", {"format": "csv"}, "results"),
    "nessus": ExportSpec("Nessus", ".nessus", {"format": "nessus"}, "results"),
}


class NessusClient:
    """Nessus 6+ REST client using documented scan export endpoints."""

    def __init__(self, url: str, verify_tls: bool = True, timeout: tuple[int, int] = (10, 120),
                 session: requests.Session | None = None) -> None:
        self.base_url = url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        try:
            # The operator has already received an explicit warning before opting out
            # of certificate validation.  Suppress urllib3's duplicate warning only
            # for this request rather than changing the process-wide warning policy.
            warning_scope = warnings.catch_warnings() if not self.verify_tls else nullcontext()
            with warning_scope:
                if not self.verify_tls:
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                response = self.session.request(method, f"{self.base_url}{path}", verify=self.verify_tls,
                                                timeout=self.timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            status = getattr(exc.response, "status_code", None)
            detail = f" (HTTP {status})" if status else ""
            raise NessusError(f"Nessus request failed{detail}: {exc}") from exc

    def authenticate_password(self, username: str, password: str) -> None:
        response = self._request("POST", "/session", json={"username": username, "password": password})
        token = response.json().get("token")
        if not token:
            raise NessusError("Nessus authentication response contained no token")
        self.session.headers["X-Cookie"] = f"token={token}"

    def authenticate_keys(self, access_key: str, secret_key: str) -> None:
        self.session.headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"
        self.list_scans()  # validate keys immediately

    def list_scans(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/scans").json()
        return list(data.get("scans", []))

    def start_export(self, scan_id: int, spec: ExportSpec) -> int:
        data = self._request("POST", f"/scans/{scan_id}/export", json=spec.payload).json()
        if "file" not in data:
            raise NessusError("Export response contained no file identifier")
        return int(data["file"])

    def wait_for_export(self, scan_id: int, file_id: int, poll_interval: float = 2,
                        poll_timeout: float = 600) -> None:
        deadline = time.monotonic() + poll_timeout
        while time.monotonic() < deadline:
            status = self._request("GET", f"/scans/{scan_id}/export/{file_id}/status").json().get("status")
            if status == "ready":
                return
            if status in {"error", "cancelled", "canceled"}:
                raise NessusError(f"Nessus export ended with status {status!r}")
            time.sleep(poll_interval)
        raise NessusError(f"Nessus export did not finish within {poll_timeout:g} seconds")

    def download_export(self, scan_id: int, file_id: int, destination: Path) -> Path:
        response = self._request("GET", f"/scans/{scan_id}/export/{file_id}/download", stream=True)
        destination = unique_path(destination)
        with destination.open("xb") as output:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    output.write(chunk)
        if destination.stat().st_size == 0:
            destination.unlink(missing_ok=True)
            raise NessusError("Nessus returned an empty export")
        return destination


class NessusCollector:
    def __init__(self, client: NessusClient, output: Path) -> None:
        self.client, self.output = client, output
        self.logger = logging.getLogger("nessus")

    def collect(self, selections: list[tuple[dict[str, Any], list[str]]]) -> ModuleResult:
        result = ModuleResult(True, targets={"url": self.client.base_url})
        exported: dict[str, list[str]] = {}
        self.output.mkdir(parents=True, exist_ok=True)
        for scan, formats in selections:
            scan_name = str(scan.get("name") or f"scan_{scan['id']}")
            safe_name = sanitize_filename(scan_name)
            scan_dir = self.output / safe_name
            scan_dir.mkdir(parents=True, exist_ok=True)
            exported[scan_name] = []
            for key in formats:
                spec = EXPORTS[key]
                try:
                    print(f"[+] Starting {spec.label} export for {scan_name}...")
                    file_id = self.client.start_export(int(scan["id"]), spec)
                    self.client.wait_for_export(int(scan["id"]), file_id)
                    path = self.client.download_export(
                        int(scan["id"]), file_id, scan_dir / f"{safe_name}_{spec.postfix}{spec.extension}")
                    result.files.append(path)
                    exported[scan_name].append(key)
                    self.logger.info("Exported scan %s as %s to %s", scan_name, spec.label, path)
                    print(f"[+] Downloaded: {path.name}")
                except Exception as exc:
                    result.success = False
                    result.reason = f"One or more exports failed: {exc}"
                    self.logger.error("Export failed for %s (%s): %s", scan_name, spec.label, exc)
                    print(f"[-] {spec.label} export failed: {exc}")
        result.details = {"scans": exported}
        return result
