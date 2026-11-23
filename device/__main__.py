"""Run fleet devices: ``python -m device press-01 press-02`` or ``python -m device --all``.

Each device provisions itself through DPS with its X.509 chain (no hub name, no
device ID, no keys configured), caches the assignment, and connects to the hub DPS chose.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import random
import signal

from azure.iot.device import X509
from azure.iot.device.aio import IoTHubDeviceClient, ProvisioningDeviceClient

from device.app import CertificateInfo, FleetDevice
from device.config import ConfigError, DeviceConfig, load_config
from device.provisioning import AssignmentStore, EnrollmentDisabled, ProvisioningError, register

logger = logging.getLogger("fleet.runner")
STAGGER_S = 3.0


class _DeviceField(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.device = getattr(record, "device", "-")
        return True


def build_device(config: DeviceConfig, device_id: str, store: AssignmentStore) -> FleetDevice:
    chain, key = config.cert_chain(device_id), config.private_key(device_id)
    if not chain.exists() or not key.exists():
        raise ConfigError(f"{device_id}: missing {chain} or {key} (run 'python -m pki device {device_id}')")
    x509 = X509(cert_file=str(chain), key_file=str(key))

    def dps_client() -> ProvisioningDeviceClient:
        return ProvisioningDeviceClient.create_from_x509_certificate(
            provisioning_host=config.dps_host, registration_id=device_id, id_scope=config.id_scope, x509=x509
        )

    def hub_client(assignment) -> IoTHubDeviceClient:
        return IoTHubDeviceClient.create_from_x509_certificate(
            x509=x509,
            hostname=assignment.assigned_hub,
            device_id=assignment.device_id,
            connection_retry=False,
        )

    return FleetDevice(
        device_id,
        store=store,
        provision=lambda: register(device_id, dps_client),
        hub_factory=hub_client,
        certificate=CertificateInfo.from_pem(chain.read_bytes()),
    )


async def _supervise(device: FleetDevice, stop: asyncio.Event, delay: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=delay)
    try:
        await device.run(stop)
    except EnrollmentDisabled:
        logger.error("enrollment disabled: device revoked, stopping", extra={"device": device.device_id})
    except ProvisioningError as exc:
        logger.error("provisioning failed: %s", exc, extra={"device": device.device_id})
    except Exception:  # one device's failure must not stop the rest of the fleet
        logger.exception("device stopped unexpectedly", extra={"device": device.device_id})


async def run(device_ids: list[str], all_devices: bool) -> None:
    config = load_config()
    ids = config.discover_devices() if all_devices else device_ids
    if not ids:
        raise ConfigError(f"no device certificates found in {config.certs_dir}")
    store = AssignmentStore(config.state_dir)
    devices = [build_device(config, device_id, store) for device_id in ids]

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)

    rng = random.Random()
    logger.info("starting %d device(s): %s", len(devices), ", ".join(ids))
    tasks = [asyncio.create_task(_supervise(d, stop, rng.uniform(0, STAGGER_S))) for d in devices]
    try:
        await asyncio.gather(*tasks)
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="device", description="Run simulated fleet devices.")
    parser.add_argument("device_ids", nargs="*", help="device ids with certificates in CERTS_DIR")
    parser.add_argument("--all", action="store_true", help="run every device found in CERTS_DIR")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    if not args.device_ids and not args.all:
        parser.error("give device ids or --all")

    handler = logging.StreamHandler()
    handler.addFilter(_DeviceField())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(device)-9s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=[handler])
    logging.getLogger("azure").setLevel(logging.WARNING)
    try:
        asyncio.run(run(args.device_ids, args.all))
    except ConfigError as exc:
        logger.error("configuration error: %s", exc)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        logger.info("interrupted")


if __name__ == "__main__":
    main()
