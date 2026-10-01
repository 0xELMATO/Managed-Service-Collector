from __future__ import annotations

import argparse
import getpass
import logging
import importlib.util
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .bloodhound import BloodHoundCollector
from .certipy import CertipyCollector
from .config import (configured_or_prompt, credential_defaults, env_bool, env_secret,
                     env_text, has_credential_environment)
from .credentials import Redactor, prompt_credentials
from .logging_setup import configure_logging
from .ldap_security import LdapSecurityCollector
from .models import Credentials, ModuleResult
from .netexec import NetExecCollector
from .pingcastle import PingCastleCollector
from .utils import create_archive, create_output_directory, parse_selection, write_manifest

MODULES = {1: "nessus", 2: "certipy", 3: "bloodhound", 4: "pingcastle", 5: "netexec", 6: "ldap"}


def show_dependencies(selected: list[str]) -> None:
    print("\n[+] Checking dependencies...")
    checks = {
        "nessus": (importlib.util.find_spec("requests") is not None, "pip install requests"),
        "certipy": (bool(shutil.which("certipy") or shutil.which("certipy-ad")), "sudo apt install certipy-ad"),
        "bloodhound": (bool(shutil.which("bloodhound-python") or shutil.which("bloodhound-ce-python")),
                       "sudo apt install bloodhound.py"),
        "pingcastle": (importlib.util.find_spec("winrm") is not None, "pip install pywinrm"),
        "netexec": (bool(shutil.which("nxc") or shutil.which("netexec")), "sudo apt install netexec"),
        "ldap": (bool(shutil.which("nxc") or shutil.which("netexec")), "sudo apt install netexec"),
    }
    for module in selected:
        present, installation = checks[module]
        print(f"[{'+' if present else '!'}] {module.title()}: {'OK' if present else 'NOT FOUND'}"
              + ("" if present else f" ({installation})"))


def yes_no(prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    value = input(prompt + suffix).strip().lower()
    return default if not value else value in {"y", "yes"}


def choose_modules() -> list[str]:
    print("""=== Security Assessment Collection Tool ===

[1] Nessus
[2] Certipy
[3] BloodHound
[4] PingCastle via WinRM
[5] SMB Sweep / NetExec
[6] LDAP Signing / Channel Binding
[7] Run all
[Q] Quit
""")
    while True:
        value = input("Select modules: ").strip()
        if value.lower() == "q":
            return []
        if value == "7":
            return list(MODULES.values())
        try:
            return [MODULES[index] for index in parse_selection(value, 6)]
        except (ValueError, KeyError):
            print("[!] Enter comma/space-separated choices (for example: 1,3,6), 7, or Q.")


def choose_next_action(zip_disabled: bool = False) -> str:
    """Ask whether to keep collecting or finalize the current assessment directory."""
    if zip_disabled:
        print("\n[1] Run another collection module\n[2] Finish (ZIP disabled by --no-zip)")
        valid = {"1": "continue", "2": "finish"}
    else:
        print("\n[1] Run another collection module\n[2] Finish and ZIP everything\n[3] Finish without ZIP")
        valid = {"1": "continue", "2": "zip", "3": "finish"}
    while True:
        choice = input("Select next action: ").strip()
        if choice in valid:
            return valid[choice]
        print(f"[!] Enter one of: {', '.join(valid)}")


def get_ad_credentials(cache: Credentials | None, module: str, module_key: str,
                       redactor: Redactor, force_prompt: bool = False) -> Credentials:
    if force_prompt:
        credentials = prompt_credentials()
        redactor.add(credentials.username, credentials.principal, credentials.password)
        return credentials
    environment_configured = has_credential_environment(module_key)
    if cache and not environment_configured and yes_no(f"Reuse existing AD credentials for {module}?", True):
        return cache
    domain, username, password = credential_defaults(module_key)
    if cache:
        domain = domain or cache.domain
        username = username or cache.username
        password = password or cache.password
    credentials = prompt_credentials(domain=domain, username=username, password=password)
    redactor.add(credentials.username, credentials.principal, credentials.password)
    return credentials


def run_nessus(root: Path, redactor: Redactor, force_prompt: bool = False) -> ModuleResult:
    try:
        from .nessus import EXPORTS, NessusClient, NessusCollector
    except ImportError:
        return ModuleResult(False, "requests is not installed; run 'pip install requests'")
    url = configured_or_prompt("Nessus URL (for example https://scanner:8834)", "MSC_NESSUS_URL",
                               force_prompt=force_prompt)
    configured_verify = None if force_prompt else env_bool("MSC_NESSUS_VERIFY_TLS")
    verify = configured_verify if configured_verify is not None else not yes_no(
        "Disable TLS certificate verification?", False)
    if not verify:
        print("[!] WARNING: Nessus TLS certificate verification is disabled")
    client = NessusClient(url, verify_tls=verify)
    try:
        access = "" if force_prompt else env_secret("MSC_NESSUS_ACCESS_KEY")
        secret = "" if force_prompt else env_secret("MSC_NESSUS_SECRET_KEY")
        username = "" if force_prompt else env_text("MSC_NESSUS_USERNAME")
        password = "" if force_prompt else env_secret("MSC_NESSUS_PASSWORD")
        use_keys = bool(access or secret) or (not (username or password) and
                                              yes_no("Use Nessus API access/secret keys instead of a password?", True))
        if use_keys:
            access = access or getpass.getpass("Nessus access key: ")
            secret = secret or getpass.getpass("Nessus secret key: ")
            redactor.add(access, secret)
            client.authenticate_keys(access, secret)
        else:
            username = username or input("Nessus username: ").strip()
            password = password or getpass.getpass("Nessus password: ")
            redactor.add(username, password)
            client.authenticate_password(username, password)
        print("[+] Authenticated to Nessus")
        scans = client.list_scans()
        if not scans:
            return ModuleResult(False, "No scans are visible to this Nessus account", {"url": url})
        print(f"[+] Found {len(scans)} scans\n\nAvailable Nessus scans:")
        for index, scan in enumerate(scans, 1):
            print(f"[{index}] {scan.get('name', 'Unnamed scan')}")
        selected = parse_selection(input("Select scans: "), len(scans))
        jobs = []
        for index in selected:
            scan = scans[index - 1]
            print(f"\nExport formats for \"{scan.get('name', 'Unnamed scan')}\":")
            print("[1] PDF by host\n[2] PDF by plugin\n[3] CSV\n[4] .nessus\n[5] All")
            choice = input("Select: ").strip()
            keys = list(EXPORTS) if choice == "5" else [list(EXPORTS)[i - 1] for i in parse_selection(choice, 4)]
            jobs.append((scan, keys))
        return NessusCollector(client, root / "nessus").collect(jobs)
    except Exception as exc:
        logging.getLogger("nessus").error("Nessus module failed: %s", exc)
        return ModuleResult(False, str(exc), {"url": url})


def run_selected_module(module: str, root: Path, redactor: Redactor,
                        cached: Credentials | None, force_prompt: bool = False) -> tuple[ModuleResult, Credentials | None]:
    """Collect one module, optionally bypassing configured defaults during a retry."""
    if module == "nessus":
        return run_nessus(root, redactor, force_prompt), cached
    if module == "certipy":
        creds = get_ad_credentials(cached, "Certipy", "CERTIPY", redactor, force_prompt)
        target = configured_or_prompt("Domain Controller / LDAP target", "MSC_CERTIPY_DC",
                                      force_prompt=force_prompt)
        return CertipyCollector(root / "certipy", redactor).collect(creds, target), creds
    if module == "bloodhound":
        creds = get_ad_credentials(cached, "BloodHound", "BLOODHOUND", redactor, force_prompt)
        dc = configured_or_prompt("Domain Controller", "MSC_BLOODHOUND_DC", force_prompt=force_prompt)
        name_server = configured_or_prompt("DNS name server/IP (optional)", "MSC_BLOODHOUND_NS",
                                           force_prompt=force_prompt)
        method = configured_or_prompt("Collection method", "MSC_BLOODHOUND_METHOD", "All", force_prompt)
        return BloodHoundCollector(root / "bloodhound", redactor).collect(
            creds, dc, method, name_server), creds
    if module == "netexec":
        creds = get_ad_credentials(cached, "NetExec", "NETEXEC", redactor, force_prompt)
        scope_file = Path(configured_or_prompt("Path to scope.txt", "MSC_NETEXEC_SCOPE_FILE",
                                               force_prompt=force_prompt))
        return NetExecCollector(root / "netexec", redactor).collect(scope_file, creds), creds
    if module == "ldap":
        creds = get_ad_credentials(cached, "LDAP security checks", "LDAP", redactor, force_prompt)
        specific_scope = env_text("MSC_LDAP_SCOPE_FILE") if not force_prompt else ""
        use_different = bool(specific_scope)
        if not specific_scope:
            use_different = yes_no("Use a different scope file containing domain controllers?", False)
        if use_different:
            scope_file = Path(specific_scope or configured_or_prompt(
                "Path to domain-controller scope file", "MSC_LDAP_SCOPE_FILE", force_prompt=True))
        else:
            collected_scope = root / "netexec" / "scope.txt"
            scope_file = collected_scope if collected_scope.is_file() else Path(configured_or_prompt(
                "Path to scope.txt", "MSC_NETEXEC_SCOPE_FILE", force_prompt=force_prompt))
        return LdapSecurityCollector(root / "ldap", redactor).collect(scope_file, creds), creds

    host = configured_or_prompt("PingCastle server IP/hostname", "MSC_PINGCASTLE_HOST",
                                force_prompt=force_prompt)
    configured_port = "" if force_prompt else env_text("MSC_PINGCASTLE_PORT")
    if configured_port:
        port = int(configured_port)
    else:
        mode = input("[1] WinRM HTTP - 5985\n[2] WinRM HTTPS - 5986\nCustom port\nSelect [2]: ").strip() or "2"
        port = 5985 if mode == "1" else 5986 if mode == "2" else int(mode)
    creds = get_ad_credentials(cached, "PingCastle", "PINGCASTLE", redactor, force_prompt)
    transport = configured_or_prompt("Authentication transport [ntlm/kerberos]",
                                     "MSC_PINGCASTLE_TRANSPORT", "ntlm", force_prompt)
    path = configured_or_prompt("PingCastle path (optional)", "MSC_PINGCASTLE_PATH",
                                force_prompt=force_prompt)
    server = configured_or_prompt("PingCastle AD domain/server", "MSC_PINGCASTLE_SERVER",
                                  creds.domain, force_prompt)
    configured_explicit = None if force_prompt else env_bool("MSC_PINGCASTLE_EXPLICIT_CREDENTIALS")
    explicit_credentials = configured_explicit if configured_explicit is not None else yes_no(
        "Pass credentials to PingCastle for the LDAP bind (recommended for NTLM WinRM)?", True)
    configured_verify = None if force_prompt else env_bool("MSC_PINGCASTLE_VERIFY_TLS")
    verify = configured_verify if configured_verify is not None else (
        True if port != 5986 else not yes_no("Ignore an untrusted WinRM HTTPS certificate?", False))
    result = PingCastleCollector(root / "pingcastle", host, port, creds, transport,
                                 verify, path, redactor, server, explicit_credentials).collect()
    return result, creds


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Collect authorized security assessment evidence")
    result.add_argument("--output", type=Path, default=Path(env_text("MSC_OUTPUT", str(Path.cwd()))),
                        help="parent output directory (default: MSC_OUTPUT or current directory)")
    result.add_argument("--no-zip", action="store_true", help="do not create the final ZIP archive")
    result.add_argument("--debug", action="store_true", help="enable debug file logging")
    result.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    pending = choose_modules()
    if not pending:
        print("[*] No modules selected; exiting.")
        return 0
    started = datetime.now().astimezone()
    root = create_output_directory(args.output.expanduser().resolve(), started)
    redactor = Redactor()
    logger = configure_logging(root, redactor, args.debug)
    logger.info("Collection started")
    results: dict[str, ModuleResult] = {}
    selected: list[str] = []
    cached: Credentials | None = None
    create_zip = not args.no_zip
    try:
        while pending:
            show_dependencies(pending)
            logger.info("Selected modules: %s", ", ".join(pending))
            for module in pending:
                if module not in selected:
                    selected.append(module)
                print(f"\n[*] Running {module} module")
                force_prompt = False
                while True:
                    try:
                        result, used_credentials = run_selected_module(
                            module, root, redactor, cached, force_prompt)
                        if result.success and used_credentials is not None:
                            cached = used_credentials
                    except Exception as exc:
                        logger.exception("Unhandled %s module error", module)
                        result = ModuleResult(False, str(exc))
                    print("[+] SUCCESS" if result.success else f"[-] FAILED: {result.reason}")
                    if result.success or not yes_no(
                            f"Retry {module} with newly prompted settings/credentials?", True):
                        break
                    force_prompt = True
                    print(f"[*] Retrying {module}; configured environment defaults will be bypassed")
                results[module] = result
            action = choose_next_action(args.no_zip)
            if action == "continue":
                pending = choose_modules()
                if pending:
                    continue
            elif action == "finish":
                create_zip = False
            else:
                create_zip = True
            break
    except KeyboardInterrupt:
        print("\n[!] Interrupted; finalizing evidence collected so far.")
        logger.warning("Collection interrupted by operator")
    finally:
        write_manifest(root, started.isoformat(), selected, results)
        archive = create_archive(root) if create_zip else None
        logger.info("Collection ended")
    print("\n=== Collection Summary ===\n")
    for name in selected:
        result = results.get(name)
        status = "NOT RUN" if result is None else "SUCCESS" if result.success else "FAILED"
        print(f"{name.title():<13}: {status}")
        if result and not result.success:
            print(f"Reason       : {result.reason}")
    count = sum(1 for path in root.rglob("*") if path.is_file())
    print(f"\nFiles collected: {count}\n\nOutput directory:\n{root}")
    if archive:
        print(f"\nZIP archive:\n{archive}")
    return 0 if results and all(item.success for item in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
