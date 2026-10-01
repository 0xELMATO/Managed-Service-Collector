from __future__ import annotations

import os
from pathlib import Path


class ConfigurationError(ValueError):
    pass


def env_text(name: str, default: str = "") -> str:
    """Return a trimmed environment setting, or its default."""
    return os.environ.get(name, default).strip()


def env_bool(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true/false, yes/no, on/off, or 1/0")


def env_secret(name: str) -> str:
    """Read a secret from NAME_FILE when set, otherwise from NAME."""
    filename = os.environ.get(f"{name}_FILE", "").strip()
    if filename:
        path = Path(filename).expanduser()
        try:
            return path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ConfigurationError(f"Could not read secret file configured by {name}_FILE: {exc}") from exc
    return os.environ.get(name, "")


def has_credential_environment(module_key: str) -> bool:
    prefixes = (f"MSC_{module_key.upper()}_", "MSC_AD_")
    suffixes = ("DOMAIN", "USERNAME", "PASSWORD", "PASSWORD_FILE")
    return any(prefix + suffix in os.environ for prefix in prefixes for suffix in suffixes)


def credential_defaults(module_key: str) -> tuple[str, str, str]:
    """Return module-specific credentials, falling back field-by-field to MSC_AD_* settings."""
    prefix = f"MSC_{module_key.upper()}_"
    domain = env_text(prefix + "DOMAIN", env_text("MSC_AD_DOMAIN"))
    username = env_text(prefix + "USERNAME", env_text("MSC_AD_USERNAME"))
    password = env_secret(prefix + "PASSWORD") or env_secret("MSC_AD_PASSWORD")
    return domain, username, password


def configured_or_prompt(label: str, variable: str, default: str = "", force_prompt: bool = False) -> str:
    if not force_prompt and variable in os.environ:
        return env_text(variable)
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ").strip() or default
