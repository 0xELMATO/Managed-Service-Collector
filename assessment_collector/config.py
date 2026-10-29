from __future__ import annotations

import os
import json
from pathlib import Path


class ConfigurationError(ValueError):
    pass


_SESSION_SETTINGS: dict[str, str] = {}
_SECRET_MARKERS = ("PASSWORD", "SECRET_KEY", "ACCESS_KEY", "TOKEN")


def default_config_path() -> Path:
    configured = os.environ.get("MSC_CONFIG_FILE", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".config" / "managed-service-collector" / "config.json"


def remember_setting(name: str, value: str) -> None:
    if name.startswith("MSC_") and value and not any(marker in name for marker in _SECRET_MARKERS):
        _SESSION_SETTINGS[name] = value


def load_saved_settings(path: Path | None = None) -> Path:
    config_path = path or default_config_path()
    if not config_path.exists():
        return config_path
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Could not load saved settings from {config_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"Saved settings in {config_path} must be a JSON object")
    for name, value in payload.items():
        if (isinstance(name, str) and name.startswith("MSC_") and isinstance(value, str)
                and not any(marker in name for marker in _SECRET_MARKERS)):
            os.environ.setdefault(name, value)
            remember_setting(name, value)
    return config_path


def save_session_settings(path: Path | None = None) -> Path:
    config_path = path or default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path.write_text(json.dumps(dict(sorted(_SESSION_SETTINGS.items())), indent=2) + "\n", encoding="utf-8")
    config_path.chmod(0o600)
    return config_path


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
        value = env_text(variable)
        remember_setting(variable, value)
        return value
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip() or default
    remember_setting(variable, value)
    return value
