# Managed Service Collector

A Python 3.11+ interactive evidence collector for **authorized** internal security assessments. It keeps Nessus, AD CS, BloodHound, PingCastle, and SMB discovery artifacts in one private timestamped directory, produces a SHA-256 manifest, and optionally creates a ZIP without deleting the source directory.

The collector does not disable security controls, evade AV/EDR, perform remote execution over SMB/WMI/PsExec, upload results, or make directory/configuration changes. PingCastle execution uses WinRM/WS-Man only.

## Kali Linux installation

```bash
git clone <repository>
cd Managed-Service-Collector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 assessment_collector.py --help
```

Install only the external tools needed for selected modules:

```bash
sudo apt update
sudo apt install netexec certipy-ad bloodhound.py
```

Package names can differ between Kali releases. Verify with `nxc --help`, `certipy --help`, and `bloodhound-python --help`. The program reads installed help before selecting version-sensitive functionality and skips a missing optional tool rather than terminating the run.

`requests` implements HTTPS to Nessus. `pywinrm` and `requests-ntlm` provide WinRM and NTLM. Optional Kerberos requires the system Kerberos libraries plus `pywinrm[kerberos]`; configure a valid ticket/cache before selecting it.

## Usage

```bash
python3 assessment_collector.py
python3 assessment_collector.py --output ./assessments
python3 assessment_collector.py --no-zip
python3 assessment_collector.py --debug
python3 assessment_collector.py --version
```

Select one or more menu numbers separated by spaces or commas. AD credentials are held only in process memory and can be reused or overridden per module. Passwords and keys are entered with `getpass`, redacted from saved output/logs, and never placed in the manifest. External Linux collectors currently require their documented `-p` argument, so the secret can briefly be visible to a sufficiently privileged local process through `/proc`; run on a trusted assessment workstation with restricted users. Saved command logging always redacts it.

## Configuration and permissions

There is intentionally no credential configuration file.

* **Output:** `--output` selects the parent; the default is the current directory. Each run directory is created mode `0700`.
* **Nessus:** enter the `https://host:8834` URL interactively. API access/secret keys are preferred; username/password `/session` authentication is also supported. The account needs permission to view and export each chosen scan. TCP connectivity and enabled scan exports are required. TLS verification is on unless the operator explicitly disables it. When disabled, the collector prints one prominent warning and suppresses only urllib3's repetitive `InsecureRequestWarning` messages for those requests; unrelated warnings remain visible. Exports use the Nessus `/scans`, `/scans/{scan_id}/export`, status, and download workflow. Each scan produces `<scan>_by_host.pdf`, `<scan>_by_plugin.pdf`, `<scan>_results.csv`, and `<scan>_results.nessus` when all formats are selected.
* **Certipy:** an ordinary authorized domain account normally suffices for read-only `find` enumeration; access can be limited by directory ACLs. The tool confirms the installed CLI exposes `find` and its output flags.
* **BloodHound:** an authorized domain account needs the directory/network read access required by the chosen collection method. The collector discovers `bloodhound-python`/`bloodhound-ce-python`, reads help, and saves output locally without upload. The operator can separately set the domain controller (`-dc`) and an optional DNS name server (`-ns`); unsupported options are reported rather than guessed.
* **NetExec:** the account needs only the desired SMB authentication/read access. The module asks for a `scope.txt` path, validates that it is a non-empty regular file, preserves a private copy with the evidence, and passes that file to NetExec as its target source. Put one supported host, IP, CIDR, or range per line according to the installed NetExec version. The module performs an SMB protocol sweep with no command-execution option. If installed help does not expose native JSON support, only the complete text artifact is promised.
* **PingCastle:** WinRM must already be enabled and allowed by the firewall. TCP 5986/HTTPS is recommended; 5985/HTTP and custom ports are supported. The account must be permitted to use WinRM, execute the existing PingCastle binary, read its generated reports, and perform PingCastle's directory health check. Supply the executable path or install it at a displayed standard location. An untrusted HTTPS certificate is rejected unless explicitly overridden.

```text
Kali
 |
 | TCP/5986 (WinRM / WS-Man)
 v
Windows Server
 |
 | PingCastle.exe --healthcheck
 v
AD environment
```

The PingCastle module retrieves files in bounded Base64 chunks over the existing WinRM session. It creates a uniquely named directory under `C:\Windows\Temp`, removes only that directory after successful retrieval, and never deletes pre-existing reports.

## Nessus export naming

Names are derived from the scan name, with unsafe filesystem characters replaced, and a descriptive postfix:

```text
Internal_Network_Scan_by_host.pdf
Internal_Network_Scan_by_plugin.pdf
Internal_Network_Scan_results.csv
Internal_Network_Scan_results.nessus
```

Existing files are not overwritten; a numeric suffix is added when necessary. PDF chapters use Nessus's `vuln_hosts_summary` and `vuln_by_plugin` export chapters.

## Output

```text
assessment_2026-09-30_103000/
├── nessus/Internal_Network_Scan/
│   ├── Internal_Network_Scan_by_host.pdf
│   ├── Internal_Network_Scan_by_plugin.pdf
│   ├── Internal_Network_Scan_results.csv
│   └── Internal_Network_Scan_results.nessus
├── certipy/{stdout.log,stderr.log,...}
├── bloodhound/{stdout.log,stderr.log,*.zip,...}
├── pingcastle/{remote_execution.log,...}
├── netexec/{scope.txt,smb_sweep.txt}
├── logs/{collection,nessus,certipy,bloodhound,pingcastle,netexec}.log
└── manifest.json
assessment_2026-09-30_103000.zip
```

The ZIP contains the top-level assessment directory. `manifest.json` records module status, non-secret targets/details, relative paths, byte sizes, and SHA-256 hashes. A module failure is reported and does not prevent later modules or finalization.

## Validation

Unit tests mock external services and require no Nessus or Windows server:

```bash
python -m pytest
python -m compileall -q assessment_collector assessment_collector.py
```

## API/tool compatibility notes

Nessus integration follows Tenable's documented asynchronous scan export sequence and checks every HTTP response. WinRM uses the public `winrm.Session(...).run_ps()` API. External collector syntax is gated by each installed program's help output; unsupported functionality is reported rather than guessed. Because upstream CLI behavior can change, validate collection in the assessment environment during pre-engagement testing.
