"""fleetctl: manage zero-touch provisioning with your Microsoft Entra ID identity.

    fleetctl group create <id> --ca <intermediate.pem> [--tag k=v ...] [--interval-ms N]
    fleetctl group show <id> | list | enable <id> | disable <id> | delete <id>
    fleetctl registrations <group-id>
    fleetctl devices [--group <id>]
    fleetctl revoke <device-id> --cert <device.cert.pem> [--reason <text>]
    fleetctl reinstate <device-id>

Results are JSON on stdout; errors go to stderr with exit code 1 (operation failed)
or 2 (invalid input or configuration).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure.core.exceptions import AzureError, ClientAuthenticationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from service.config import ConfigError, ServiceConfig, load_config
from service.dps import DPS_API_VERSION, DPS_SCOPE, DpsService, GroupSpec
from service.hub import HUB_API_VERSION, HUB_SCOPE, HubRegistry
from service.rest import ApiError, RestClient

logger = logging.getLogger("fleet.fleetctl")


@dataclass
class Services:
    dps: DpsService
    hub: HubRegistry
    hub_hostname: str


ServicesFactory = Callable[[ServiceConfig], AbstractContextManager[Services]]


def _tag(text: str) -> tuple[str, str]:
    key, sep, value = text.partition("=")
    if not sep or not key or not value:
        raise argparse.ArgumentTypeError("expected key=value")
    return key, value


def read_certificate(path: Path, *, ca: bool) -> tuple[str, x509.Certificate]:
    """Load the first PEM certificate and check it is the kind expected (CA or leaf)."""
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    if is_ca != ca:
        raise ValueError(f"{path} is {'a CA' if is_ca else 'not a CA'} certificate")
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), cert


def _common_name(cert: x509.Certificate) -> str:
    return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fleetctl", description="Zero-touch fleet provisioning.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    commands = parser.add_subparsers(dest="command", required=True)

    group = commands.add_parser("group", help="enrollment groups").add_subparsers(
        dest="action", required=True
    )
    create = group.add_parser("create", help="create or update an X.509 enrollment group")
    create.add_argument("group_id")
    create.add_argument("--ca", type=Path, required=True, help="intermediate CA certificate (PEM)")
    create.add_argument("--tag", type=_tag, action="append", default=[], help="initial twin tag key=value")
    create.add_argument(
        "--interval-ms",
        type=int,
        default=60_000,
        help="initial desired telemetry interval (default 60000: 5 devices fit IoT Hub F1, 8,000 msgs/day)",
    )
    group.add_parser("list", help="list enrollment groups")
    for action in ("show", "enable", "disable", "delete"):
        group.add_parser(action, help=f"{action} an enrollment group").add_argument("group_id")

    commands.add_parser("registrations", help="registration records of a group").add_argument("group_id")
    devices = commands.add_parser("devices", help="devices in the hub")
    devices.add_argument("--group", help="only devices provisioned by this enrollment group")

    revoke = commands.add_parser("revoke", help="block one device: DPS and IoT Hub")
    revoke.add_argument("device_id")
    revoke.add_argument("--cert", type=Path, required=True, help="the device's certificate (PEM)")
    revoke.add_argument("--reason", default="revoked by operator")
    commands.add_parser("reinstate", help="undo a revocation").add_argument("device_id")
    return parser


@contextmanager
def _default_services(config: ServiceConfig) -> Iterator[Services]:
    from azure.identity import DefaultAzureCredential

    with (
        DefaultAzureCredential() as credential,
        RestClient(config.dps_endpoint, credential, DPS_SCOPE, DPS_API_VERSION) as dps,
        RestClient(f"https://{config.hub_hostname}", credential, HUB_SCOPE, HUB_API_VERSION) as hub,
    ):
        yield Services(DpsService(dps), HubRegistry(hub), config.hub_hostname)


def _hub_status(services: Services, device_id: str, enabled: bool, reason: str = "") -> Any:
    try:
        return services.hub.set_enabled(device_id, enabled, reason)["status"]
    except ApiError as exc:
        if exc.status == 404:
            return "not registered in hub"
        raise


def _execute(args: argparse.Namespace, services: Services) -> Any:
    dps, hub = services.dps, services.hub
    if args.command == "group":
        if args.action == "create":
            pem, _ = read_certificate(args.ca, ca=True)
            spec = GroupSpec(
                group_id=args.group_id,
                signing_certificate_pem=pem,
                iot_hub=services.hub_hostname,
                tags=dict(args.tag),
                desired={"telemetryIntervalMs": args.interval_ms},
            )
            return dps.put_group(spec)
        if args.action == "list":
            return dps.list_groups()
        if args.action == "show":
            return dps.get_group(args.group_id)
        if args.action in ("enable", "disable"):
            return dps.set_group_enabled(args.group_id, args.action == "enable")
        dps.delete_group(args.group_id)
        return {"deleted": args.group_id}
    if args.command == "registrations":
        return dps.list_registrations(args.group_id)
    if args.command == "devices":
        return hub.list_devices(args.group)
    if args.command == "revoke":
        pem, cert = read_certificate(args.cert, ca=False)
        if _common_name(cert) != args.device_id:
            raise ValueError(f"{args.cert} belongs to {_common_name(cert)!r}, not {args.device_id!r}")
        enrollment = dps.revoke(args.device_id, pem)
        return {**enrollment, "hubStatus": _hub_status(services, args.device_id, False, args.reason)}
    removed = dps.reinstate(args.device_id)
    return {
        "deviceId": args.device_id,
        "revocationRemoved": removed,
        "hubStatus": _hub_status(services, args.device_id, True),
    }


def main(
    argv: Sequence[str] | None = None,
    services_factory: ServicesFactory = _default_services,
    config_loader: Callable[[], ServiceConfig] = load_config,
) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = config_loader()
        with services_factory(config) as services:
            result = _execute(args, services)
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ClientAuthenticationError as exc:
        print(f"error: not signed in to Azure ({exc.message}); run 'az login'", file=sys.stderr)
        return 1
    except (ApiError, AzureError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    print(json.dumps(result, indent=2, default=str))
    return 0


def console() -> None:
    raise SystemExit(main())
