from pathlib import Path

import pytest

from assessment_collector.credentials import Redactor
from assessment_collector.models import Credentials
from assessment_collector.netexec import NetExecCollector, filter_signing_disabled
from assessment_collector.pingcastle import PingCastleCollector


def test_netexec_command_is_argument_array(tmp_path: Path):
    collector = NetExecCollector(tmp_path, Redactor())
    command = collector.build_command("nxc", tmp_path / "scope.txt", Credentials("ACME", "audit", "pw"))
    assert command == ["nxc", "smb", str(tmp_path / "scope.txt"), "-u", "audit", "-p", "pw", "-d", "ACME"]


def test_smb_output_keeps_only_signing_disabled_hosts():
    output = ("SMB 10.0.0.1 445 DC01 [*] Windows (signing:True)\n"
              "\x1b[32mSMB 10.0.0.2 445 FILE01 [*] Windows (signing:False)\x1b[0m\n"
              "SMB 10.0.0.3 445 FILE02 [*] Windows (signing:disabled)\n")
    assert filter_signing_disabled(output).splitlines() == [
        "SMB 10.0.0.2 445 FILE01 [*] Windows (signing:False)",
        "SMB 10.0.0.3 445 FILE02 [*] Windows (signing:disabled)",
    ]


def test_pingcastle_without_pywinrm_has_clear_error(tmp_path: Path, monkeypatch):
    collector = PingCastleCollector(tmp_path, "server", 5985, Credentials("D", "u", "p"))
    monkeypatch.setitem(__import__("sys").modules, "winrm", None)
    with pytest.raises(RuntimeError, match="pywinrm not installed"):
        collector.connect()


def test_missing_netexec(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("assessment_collector.netexec.find_tool", lambda *_: None)
    result = NetExecCollector(tmp_path, Redactor()).collect(tmp_path / "scope.txt", Credentials("", "u", "p"))
    assert not result.success and "not found" in result.reason


def test_bloodhound_name_server_argument(tmp_path: Path):
    from assessment_collector.bloodhound import BloodHoundCollector

    command = BloodHoundCollector(tmp_path, Redactor()).build_command(
        "bloodhound-python", "-u -p -d -c -dc -ns", Credentials("ACME", "audit", "pw"),
        "dc01.acme.test", "All", "10.0.0.53",
    )
    assert command[-4:] == ["-dc", "dc01.acme.test", "-ns", "10.0.0.53"]


def test_ldap_checker_command_is_read_only(tmp_path: Path):
    from assessment_collector.ldap_security import LdapSecurityCollector

    command = LdapSecurityCollector(tmp_path, Redactor()).build_command(
        "nxc", "dc01.acme.test", Credentials("ACME", "audit", "pw"))
    assert command == ["nxc", "ldap", "dc01.acme.test", "-u", "audit", "-p", "pw",
                       "-d", "ACME", "-M", "ldap-checker"]


def test_pingcastle_progress_clixml_is_not_reported_as_an_error():
    from assessment_collector.pingcastle import _powershell_error

    progress = (b'#< CLIXML\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
                b'<Obj S="progress"><MS><S N="Message">Preparing modules</S></MS></Obj></Objs>')
    assert _powershell_error(progress) == ""


def test_pingcastle_healthcheck_includes_server(tmp_path: Path):
    from types import SimpleNamespace

    collector = PingCastleCollector(
        tmp_path, "runner", 5985, Credentials("ACME", "audit", "pw"),
        path=r"C:\Tools\PingCastle\PingCastle.exe", server="domain.local",
    )
    collector.pingcastle_path = collector.requested_path
    scripts = []

    class Session:
        def run_ps(self, script):
            scripts.append(script)
            if script.endswith("--help"):
                return SimpleNamespace(status_code=0,
                                       std_out=b"--healthcheck --server --user --password", std_err=b"")
            return SimpleNamespace(status_code=0, std_out=b"done", std_err=b"")

    collector.session = Session()
    collector.execute_pingcastle()
    assert "--healthcheck --server 'domain.local' --user 'ACME\\audit' --password 'pw'" in scripts[1]
    assert "pw" not in (tmp_path / "remote_execution.log").read_text()


def test_pingcastle_detects_exit_zero_ldap_bind_failure():
    from assessment_collector.pingcastle import _pingcastle_failure

    output = ("Could not query Active Directory. An operations error occurred. "
              "In order to perform this operation a successful bind must be completed on the connection.")
    assert "could not bind" in _pingcastle_failure(output).lower()
