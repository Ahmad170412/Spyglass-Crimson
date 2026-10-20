from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

PROVIDERS: dict[str, str] = {
    "shodan": "SPYGLASS_SHODAN_KEY",
    "censys": "SPYGLASS_CENSYS_KEY",
    "ipinfo": "SPYGLASS_IPINFO_TOKEN",
    "otx": "SPYGLASS_OTX_KEY",
    "urlscan": "SPYGLASS_URLSCAN_KEY",
}

SERVICE_NAME = "spyglass-crimson"


class CredentialStore:
    """Keys never enter SQLite and are never returned by the API.

    Resolution order is environment, keyring, then a local 0600 fallback file.
    The file fallback keeps headless/dev runs working when Keychain is unavailable.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        service: str = SERVICE_NAME,
        use_keyring: bool = True,
    ):
        self.path = Path(path)
        self.service = service
        self.use_keyring = use_keyring

    def _keyring(self):
        if not self.use_keyring:
            return None
        try:
            import keyring
        except Exception:
            return None
        return keyring

    def _read_file(self) -> dict[str, str]:
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if isinstance(v, str) and v}

    def _write_file(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        tmp.replace(self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def get(self, provider: str) -> str | None:
        provider = provider.strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")
        env_value = os.environ.get(PROVIDERS[provider])
        if env_value:
            return env_value.strip()
        keyring = self._keyring()
        if keyring is not None:
            try:
                value = keyring.get_password(self.service, provider)
                if value:
                    return value
            except Exception:
                pass
        return self._read_file().get(provider)

    def set(self, provider: str, secret: str) -> None:
        provider = provider.strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")
        secret = secret.strip()
        if not secret:
            raise ValueError("Secret cannot be empty")
        keyring = self._keyring()
        if keyring is not None:
            try:
                keyring.set_password(self.service, provider, secret)
                # Remove any stale file copy after a successful keyring write.
                data = self._read_file()
                if provider in data:
                    data.pop(provider, None)
                    self._write_file(data)
                return
            except Exception:
                pass
        data = self._read_file()
        data[provider] = secret
        self._write_file(data)

    def delete(self, provider: str) -> None:
        provider = provider.strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")
        keyring = self._keyring()
        if keyring is not None:
            try:
                keyring.delete_password(self.service, provider)
            except Exception:
                pass
        data = self._read_file()
        if provider in data:
            data.pop(provider, None)
            self._write_file(data)

    def configured(self) -> dict[str, bool]:
        return {provider: bool(self.get(provider)) for provider in PROVIDERS}

    def public_status(self) -> dict[str, Any]:
        return {"configured": self.configured(), "backend": self.backend}

    @property
    def backend(self) -> str:
        if self._keyring() is not None:
            return "keyring"
        return "file"
