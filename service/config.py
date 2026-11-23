"""fleetctl configuration from the environment (or a local .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ServiceConfig:
    dps_endpoint: str
    hub_hostname: str


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set (run infra/deploy.ps1 or see .env.example)")
    return value


def load_config() -> ServiceConfig:
    from dotenv import load_dotenv

    load_dotenv()
    dps = _required("DPS_SERVICE_HOSTNAME").removeprefix("https://").rstrip("/")
    hub = _required("IOTHUB_HOSTNAME").removeprefix("https://").rstrip("/")
    return ServiceConfig(dps_endpoint=f"https://{dps}", hub_hostname=hub)
