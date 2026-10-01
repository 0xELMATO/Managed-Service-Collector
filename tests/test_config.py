from pathlib import Path

import pytest

from assessment_collector.config import (ConfigurationError, credential_defaults,
                                         env_bool, env_secret)
from assessment_collector.credentials import Redactor
from assessment_collector.main import get_ad_credentials


def test_module_credentials_override_shared_environment(monkeypatch):
    monkeypatch.setenv("MSC_AD_DOMAIN", "AD.EXAMPLE")
    monkeypatch.setenv("MSC_AD_USERNAME", "shared")
    monkeypatch.setenv("MSC_AD_PASSWORD", "shared-secret")
    monkeypatch.setenv("MSC_BLOODHOUND_USERNAME", "bloodhound")
    assert credential_defaults("BLOODHOUND") == ("AD.EXAMPLE", "bloodhound", "shared-secret")


def test_secret_file_takes_precedence(tmp_path: Path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("MSC_AD_PASSWORD", "from-environment")
    monkeypatch.setenv("MSC_AD_PASSWORD_FILE", str(secret))
    assert env_secret("MSC_AD_PASSWORD") == "from-file"


@pytest.mark.parametrize(("value", "expected"), [("yes", True), ("0", False)])
def test_boolean_environment(monkeypatch, value, expected):
    monkeypatch.setenv("MSC_TEST_BOOLEAN", value)
    assert env_bool("MSC_TEST_BOOLEAN") is expected


def test_invalid_boolean_environment(monkeypatch):
    monkeypatch.setenv("MSC_TEST_BOOLEAN", "sometimes")
    with pytest.raises(ConfigurationError):
        env_bool("MSC_TEST_BOOLEAN")


def test_complete_environment_credentials_do_not_prompt(monkeypatch):
    monkeypatch.setenv("MSC_AD_DOMAIN", "AD.EXAMPLE")
    monkeypatch.setenv("MSC_AD_USERNAME", "auditor")
    monkeypatch.setenv("MSC_AD_PASSWORD", "secret")
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("input prompt was called"))
    monkeypatch.setattr("getpass.getpass", lambda *_: pytest.fail("password prompt was called"))
    credentials = get_ad_credentials(None, "Certipy", "CERTIPY", Redactor())
    assert credentials.principal == r"AD.EXAMPLE\auditor"
