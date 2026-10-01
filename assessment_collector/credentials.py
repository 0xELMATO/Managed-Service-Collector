from __future__ import annotations

import getpass
from collections.abc import Iterable

from .models import Credentials


class Redactor:
    """Best-effort removal of secrets and identities before persistent output."""

    def __init__(self, values: Iterable[str] = ()) -> None:
        self._values: set[str] = {v for v in values if v}

    def add(self, *values: str) -> None:
        self._values.update(v for v in values if v)

    def redact(self, value: str) -> str:
        result = value
        for secret in sorted(self._values, key=len, reverse=True):
            result = result.replace(secret, "[REDACTED]")
        return result


def prompt_credentials(domain_label: str = "Domain", domain: str = "", username: str = "",
                       password: str = "") -> Credentials:
    if not domain:
        domain = input(f"{domain_label}: ").strip()
    if not username:
        username = input("Username: ").strip()
    if not password:
        password = getpass.getpass("Password: ")
    return Credentials(domain, username, password)
