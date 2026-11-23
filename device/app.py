"""One fleet device: provision (or reuse the cached assignment), connect, operate, recover.

Lifecycle:
    cached assignment ──► connect to hub ──► session (twin, telemetry, methods)
          │ none               │ identity rejected / repeated failures
          ▼                    ▼
    register with DPS ◄── clear cache          disabled enrollment ──► stop (revoked)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from azure.iot.device import MethodResponse, exceptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from device.machine import MIN_INTERVAL_MS, MachineSimulator, MachineState
from device.provisioning import (
    DEFAULT_BACKOFF,
    FINAL_ERRORS,
    TRANSIENT_ERRORS,
    Assignment,
    AssignmentStore,
    Backoff,
    ProvisioningError,
)
from device.telemetry import build_payload, to_message

FIRMWARE_VERSION = "1.0.0"
MAX_INTERVAL_MS = 3_600_000
CONNECT_FAILURES_BEFORE_REPROVISION = 3

# Failures worth reconnecting after (CredentialError is handled first). Seen live: with
# connection_retry=False a drop cancels in-flight sends (OperationCancelled), and a hub over
# its daily quota answers 403, which the SDK raises as a generic ClientError.
RECOVERABLE: tuple[type[Exception], ...] = (
    *TRANSIENT_ERRORS,
    exceptions.NoConnectionError,
    exceptions.OperationCancelled,
    exceptions.ClientError,
)


def _describe(error: BaseException) -> str:
    cause = error.__cause__
    return f"{type(error).__name__}: {cause or error}" if cause else f"{type(error).__name__}: {error}"


logger = logging.getLogger("fleet.device")


class HubClient(Protocol):
    on_twin_desired_properties_patch_received: Any
    on_method_request_received: Any

    async def connect(self) -> None: ...
    async def shutdown(self) -> None: ...
    async def send_message(self, message: Any) -> None: ...
    async def get_twin(self) -> dict: ...
    async def patch_twin_reported_properties(self, patch: dict) -> None: ...
    async def send_method_response(self, response: Any) -> None: ...


HubFactory = Callable[[Assignment], HubClient]
Provisioner = Callable[[], Awaitable[Assignment]]


class SessionEnd(Enum):
    STOPPED = "stopped"
    REPROVISION = "reprovision"
    DROPPED = "dropped"


@dataclass(frozen=True)
class CertificateInfo:
    thumbprint: str
    issuer: str
    not_after: str

    @classmethod
    def from_pem(cls, pem: bytes) -> CertificateInfo:
        leaf = x509.load_pem_x509_certificates(pem)[0]
        issuer = leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cls(
            thumbprint=leaf.fingerprint(hashes.SHA256()).hex().upper(),
            issuer=str(issuer[0].value) if issuer else leaf.issuer.rfc4514_string(),
            not_after=leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        )


def _ack(value: Any, code: int, version: int, description: str) -> dict:
    return {"value": value, "ac": code, "av": version, "ad": description}


class FleetDevice:
    def __init__(
        self,
        device_id: str,
        *,
        store: AssignmentStore,
        provision: Provisioner,
        hub_factory: HubFactory,
        certificate: CertificateInfo,
        simulator: MachineSimulator | None = None,
        backoff: Backoff = DEFAULT_BACKOFF,
        rng: random.Random | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.device_id = device_id
        self._store = store
        self._provision = provision
        self._hub_factory = hub_factory
        self._certificate = certificate
        self._machine = simulator or MachineSimulator(MachineState())
        self._backoff = backoff
        self._rng = rng or random.Random()
        self._sleep = sleep
        self._log = logging.LoggerAdapter(logger, {"device": device_id})
        self._sequence = 0
        self._reprovision = asyncio.Event()
        self._client: HubClient | None = None
        self._delivered = False

    @property
    def interval_ms(self) -> int:
        return self._machine.state.interval_ms

    async def run(self, stop: asyncio.Event) -> None:
        """Run until ``stop`` is set.

        Raises EnrollmentDisabled when the device is revoked and CertificateRejected when DPS
        refuses its certificate; every other failure is retried with capped backoff.
        """
        failures = 0
        outages = 0
        drops = 0
        while not stop.is_set():
            try:
                assignment = await self._assignment()
            except FINAL_ERRORS:
                raise
            except ProvisioningError as exc:
                outages += 1
                await self._pause(outages, stop, f"provisioning failed ({exc})")
                continue
            outages = 0
            client = self._hub_factory(assignment)
            self._client = client
            try:
                try:
                    await client.connect()
                except exceptions.CredentialError as exc:
                    self._log.warning(
                        "hub %s rejected the identity (%s); re-provisioning", assignment.assigned_hub, exc
                    )
                    self._store.clear(self.device_id)
                    continue
                except RECOVERABLE as exc:
                    failures += 1
                    if failures >= CONNECT_FAILURES_BEFORE_REPROVISION:
                        self._log.warning("%d connect failures (%s); re-provisioning", failures, exc)
                        self._store.clear(self.device_id)
                        failures = 0
                        continue
                    await self._pause(failures, stop, f"connect failed ({_describe(exc)})")
                    continue
                failures = 0
                self._log.info("connected to %s", assignment.assigned_hub)
                end = await self._session(client, assignment, stop)
            finally:
                self._client = None
                with contextlib.suppress(Exception):
                    await client.shutdown()

            if end is SessionEnd.REPROVISION:
                self._store.clear(self.device_id)
            elif end is SessionEnd.DROPPED:
                # back off further while sessions keep failing before any telemetry is delivered
                # (a hub over quota accepts connections but rejects every operation)
                drops = 1 if self._delivered else drops + 1
                await self._pause(drops, stop, "connection lost")

    async def _assignment(self) -> Assignment:
        cached = self._store.load(self.device_id)
        if cached is not None:
            return cached
        self._log.info("provisioning through DPS")
        assignment = await self._provision()
        self._store.save(assignment)
        self._log.info("assigned to %s (%s)", assignment.assigned_hub, assignment.sub_status)
        return assignment

    async def _pause(self, attempt: int, stop: asyncio.Event, reason: str) -> None:
        delay = self._backoff.delay(attempt - 1, self._rng)
        self._log.warning("%s; retrying in %.1fs", reason, delay)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=delay)

    async def _session(self, client: HubClient, assignment: Assignment, stop: asyncio.Event) -> SessionEnd:
        self._reprovision.clear()
        self._delivered = False
        client.on_twin_desired_properties_patch_received = self.on_desired_patch
        client.on_method_request_received = self.on_method_request
        try:
            twin = await client.get_twin()
            await client.patch_twin_reported_properties(self._startup_report(assignment, twin))
            while True:
                self._machine.step()
                snapshot = self._machine.snapshot()
                health = str(snapshot.pop("health"))
                reading = {k: v for k, v in snapshot.items() if k not in ("wear", "running")}
                self._sequence += 1
                await client.send_message(
                    to_message(build_payload(self.device_id, self._sequence, reading, health))
                )
                self._delivered = True
                if await self._wait(stop, self.interval_ms / 1000):
                    return SessionEnd.STOPPED
                if self._reprovision.is_set():
                    self._log.info("re-provisioning on request")
                    return SessionEnd.REPROVISION
        except exceptions.CredentialError as exc:
            self._log.warning("identity rejected during session (%s)", exc)
            return SessionEnd.REPROVISION
        except RECOVERABLE as exc:
            self._log.warning("session ended (%s)", _describe(exc))
            return SessionEnd.DROPPED

    async def _wait(self, stop: asyncio.Event, seconds: float) -> bool:
        """Sleep until the interval passes, a re-provision is requested, or ``stop`` is set."""
        waiters = [asyncio.ensure_future(stop.wait()), asyncio.ensure_future(self._reprovision.wait())]
        try:
            await asyncio.wait(waiters, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()
        return stop.is_set()

    def _startup_report(self, assignment: Assignment, twin: dict) -> dict:
        report: dict[str, Any] = {
            "firmwareVersion": FIRMWARE_VERSION,
            "connectivity": "online",
            "provisioning": {
                "assignedHub": assignment.assigned_hub,
                "subStatus": assignment.sub_status,
                "provisionedAt": assignment.provisioned_at,
            },
            "certificate": {
                "thumbprint": self._certificate.thumbprint,
                "issuer": self._certificate.issuer,
                "notAfter": self._certificate.not_after,
            },
        }
        desired = twin.get("desired", {})
        if "telemetryIntervalMs" in desired:
            report["telemetryIntervalMs"] = self._apply_interval(
                desired["telemetryIntervalMs"], desired.get("$version", 0)
            )
        return report

    def _apply_interval(self, value: Any, version: int) -> dict:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not MIN_INTERVAL_MS <= value <= MAX_INTERVAL_MS
        ):
            self._log.warning("rejected telemetryIntervalMs=%r", value)
            return _ack(
                self.interval_ms, 400, version, f"must be an integer {MIN_INTERVAL_MS}-{MAX_INTERVAL_MS}"
            )
        self._machine.state.interval_ms = value
        return _ack(value, 200, version, "applied")

    async def on_desired_patch(self, patch: dict) -> None:
        if "telemetryIntervalMs" not in patch or self._client is None:
            return
        ack = self._apply_interval(patch["telemetryIntervalMs"], patch.get("$version", 0))
        with contextlib.suppress(Exception):
            await self._client.patch_twin_reported_properties({"telemetryIntervalMs": ack})

    async def on_method_request(self, request: Any) -> None:
        if self._client is None:
            return
        if request.name == "Reprovision":
            status, payload = 200, {"accepted": True}
        else:
            status, payload = 404, {"error": f"unknown method: {request.name}"}
        with contextlib.suppress(Exception):
            await self._client.send_method_response(
                MethodResponse.create_from_method_request(request, status, payload)
            )
        if status == 200:
            self._reprovision.set()
