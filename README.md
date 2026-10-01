# Managed Service Collector

A Python 3.11+ interactive evidence collector for **authorized** internal security assessments. It keeps Nessus, AD CS, BloodHound, PingCastle, SMB-signing, and LDAP-signing/channel-binding artifacts in one private timestamped directory, produces a SHA-256 manifest, and optionally creates a ZIP without deleting the source directory.

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

After the selected module or batch completes, the same timestamped assessment remains open and the tool asks whether to run another module, finish and ZIP everything collected so far, or finish without a ZIP. Selecting another module does not create an intermediate archive. `--no-zip` removes the ZIP choice but still lets the operator continue collecting additional modules into the same directory. When a module fails—for example because a scope file does not exist or authentication is rejected—the tool asks whether to retry that module. A retry prompts again for its settings and credentials and deliberately bypasses environment defaults so a bad configured value does not cause an endless loop. The operator can decline and continue to the next selected module.

```text
[1] Run another collection module
[2] Finish and ZIP everything
[3] Finish without ZIP
```

## Configuration and permissions

There is intentionally no credential configuration file.

### Environment variables

Every configured value is checked before an interactive prompt. Export variables in the current terminal, place them in a protected launcher/service environment, or prefix them on the command invocation. Do **not** commit secrets to shell profiles, `.env` files, source control, or shell scripts. Interactive `getpass` entry remains the safest default. For automation, prefer the `*_PASSWORD_FILE`, `*_ACCESS_KEY_FILE`, and `*_SECRET_KEY_FILE` variants pointing to owner-readable files (for example, mode `0600`) over direct secret environment variables.

```bash
# Shared AD defaults used by Certipy, BloodHound, NetExec, LDAP, and PingCastle
export MSC_AD_DOMAIN='CONTOSO.LOCAL'
export MSC_AD_USERNAME='auditor'
export MSC_AD_PASSWORD_FILE="$HOME/.secrets/assessment-ad-password"

# Common targets and module settings
export MSC_CERTIPY_DC='10.10.10.10'
export MSC_BLOODHOUND_DC='dc01.contoso.local'
export MSC_BLOODHOUND_NS='10.10.10.10'
export MSC_BLOODHOUND_METHOD='All'
export MSC_NETEXEC_SCOPE_FILE="$PWD/scope.txt"
# Optional DC-only scope; when omitted the LDAP module asks whether to use a
# different DC scope and otherwise reuses MSC_NETEXEC_SCOPE_FILE/scope.txt.
export MSC_LDAP_SCOPE_FILE="$PWD/domain-controllers.txt"

export MSC_PINGCASTLE_HOST='management01.contoso.local'
export MSC_PINGCASTLE_PORT='5986'
export MSC_PINGCASTLE_TRANSPORT='ntlm'
export MSC_PINGCASTLE_PATH='C:\Tools\PingCastle\PingCastle.exe'
export MSC_PINGCASTLE_SERVER='contoso.local'
export MSC_PINGCASTLE_EXPLICIT_CREDENTIALS='true'
export MSC_PINGCASTLE_VERIFY_TLS='true'

export MSC_OUTPUT="$PWD/assessments"
python3 assessment_collector.py
```

Module-specific AD credentials override the shared values field by field. Supported prefixes are `MSC_CERTIPY_`, `MSC_BLOODHOUND_`, `MSC_NETEXEC_`, `MSC_LDAP_`, and `MSC_PINGCASTLE_`, each with `DOMAIN`, `USERNAME`, `PASSWORD`, or `PASSWORD_FILE`. For example:

```bash
export MSC_PINGCASTLE_USERNAME='pingcastle-auditor'
export MSC_PINGCASTLE_PASSWORD_FILE="$HOME/.secrets/pingcastle-password"
```

Nessus can use API keys or a password. API keys take precedence when configured:

```bash
export MSC_NESSUS_URL='https://nessus.contoso.local:8834'
export MSC_NESSUS_ACCESS_KEY_FILE="$HOME/.secrets/nessus-access-key"
export MSC_NESSUS_SECRET_KEY_FILE="$HOME/.secrets/nessus-secret-key"
export MSC_NESSUS_VERIFY_TLS='true'

# Alternative password authentication:
# export MSC_NESSUS_USERNAME='api-auditor'
# export MSC_NESSUS_PASSWORD_FILE="$HOME/.secrets/nessus-password"
```

Boolean variables accept `true/false`, `yes/no`, `on/off`, or `1/0`. Command-line `--output` overrides `MSC_OUTPUT`. Environment variables are inherited by child processes and may be readable by sufficiently privileged local users, so unset direct secret variables after the run (`unset MSC_AD_PASSWORD MSC_NESSUS_PASSWORD`) and prefer secret files or interactive prompts.

* **Output:** `--output` selects the parent; otherwise `MSC_OUTPUT` is used when set, followed by the current-directory default. Each run directory is created mode `0700`.
* **Nessus:** enter the `https://host:8834` URL interactively. API access/secret keys are preferred; username/password `/session` authentication is also supported. The account needs permission to view and export each chosen scan. TCP connectivity and enabled scan exports are required. TLS verification is on unless the operator explicitly disables it. When disabled, the collector prints one prominent warning and suppresses only urllib3's repetitive `InsecureRequestWarning` messages for those requests; unrelated warnings remain visible. Exports use the Nessus `/scans`, `/scans/{scan_id}/export`, status, and download workflow. Each scan produces `<scan>_by_host.pdf`, `<scan>_by_plugin.pdf`, `<scan>_results.csv`, and `<scan>_results.nessus` when all formats are selected.
* **Certipy:** an ordinary authorized domain account normally suffices for read-only `find` enumeration; access can be limited by directory ACLs. The tool confirms the installed CLI exposes `find` and its output flags.
* **BloodHound:** an authorized domain account needs the directory/network read access required by the chosen collection method. The collector discovers `bloodhound-python`/`bloodhound-ce-python`, reads help, and saves output locally without upload. The operator can separately set the domain controller (`-dc`) and an optional DNS name server (`-ns`); unsupported options are reported rather than guessed.
* **NetExec SMB sweep:** the account needs only the desired SMB authentication/read access. The module asks for a `scope.txt` path, validates that it is a non-empty regular file, preserves a private copy with the evidence, and passes that file to NetExec as its target source. Put one supported host, IP, CIDR, or range per line according to the installed NetExec version. The saved `smb_sweep.txt` and JSON data contain only hosts for which NetExec explicitly reports SMB signing as `False`, `disabled`, or `no`; ANSI color codes are removed. The module uses no command-execution option.
* **LDAP signing/channel binding:** this separate module asks whether the domain controllers have a different scope file. If skipped, it reuses the SMB `scope.txt` (preferring the copy already preserved by this run); otherwise it accepts a DC-only file or `MSC_LDAP_SCOPE_FILE`. It invokes NetExec's read-only `ldap-checker`, first checking `nxc ldap -L` and failing clearly if unavailable. The saved text report contains only responding DC lines that mention LDAP signing or channel binding; generic authentication/banner lines are omitted. The input scope is preserved as `ldap/dc_scope.txt`. The account requires LDAP authentication and ordinary directory connectivity; the collector does not modify LDAP configuration.
* **PingCastle:** WinRM must already be enabled and allowed by the firewall. TCP 5986/HTTPS is recommended; 5985/HTTP and custom ports are supported. The account must be permitted to use WinRM, execute the existing PingCastle binary, read its generated reports, and perform PingCastle's directory health check. Supply the executable path or install it at a displayed standard location. The collector separately prompts for the AD DNS domain/server and executes the installed tool as `PingCastle.exe --healthcheck --server <domain>` only after confirming both options in its help output. This value defaults to the reused credential domain but can be overridden (for example, `domain.local`). NTLM WinRM cannot delegate the authenticated logon to LDAP (the “double hop”), so the default is to pass the in-memory assessment credentials through PingCastle's detected `--user`/`--password` options. They are sent inside the encrypted WinRM channel and redacted from logs, but can be briefly visible to administrators inspecting the Windows process command line. Environments with correctly configured Kerberos/CredSSP delegation may opt out. The collector also treats PingCastle's “Could not query Active Directory” output as failure even when that PingCastle release incorrectly exits with code 0. An untrusted HTTPS certificate is rejected unless explicitly overridden.

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
├── ldap/{dc_scope.txt,ldap_signing_channel_binding.txt}
├── logs/{collection,nessus,certipy,bloodhound,pingcastle,netexec,ldap}.log
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
