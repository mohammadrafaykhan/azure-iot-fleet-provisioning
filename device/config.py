"""Device fleet configuration from the environment (or a local .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DPS_HOST = "global.azure-devices-provisioning.net"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class DeviceConfig:
    id_scope: str
    dps_host: str
    certs_dir: Path
    state_dir: Path

    def cert_chain(self, device_id: str) -> Path:
        return self.certs_dir / f"{device_id}.fullchain.pem"

    def private_key(self, device_id: str) -> Path:
        return self.certs_dir / f"{device_id}.key.pem"

    def discover_devices(self) -> list[str]:
        suffix = ".fullchain.pem"
        return sorted(path.name[: -len(suffix)] for path in self.certs_dir.glob(f"*{suffix}"))


def load_config() -> DeviceConfig:
    from dotenv import load_dotenv

    load_dotenv()
    id_scope = os.getenv("DPS_ID_SCOPE", "").strip()
    if not id_scope:
        raise ConfigError("DPS_ID_SCOPE is not set (run infra/deploy.ps1 or see .env.example)")
    return DeviceConfig(
        id_scope=id_scope,
        dps_host=os.getenv("DPS_HOST", DEFAULT_DPS_HOST).strip() or DEFAULT_DPS_HOST,
        certs_dir=Path(os.getenv("CERTS_DIR", "certs")),
        state_dir=Path(os.getenv("STATE_DIR", "state")),
    )
