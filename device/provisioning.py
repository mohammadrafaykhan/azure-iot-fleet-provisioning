"""Zero-touch provisioning through DPS, following its device guidance.

* Provision once and cache the assignment; do not call DPS on every boot.
* Re-provision only when the hub rejects the identity, or on operator request.
* Retry transient failures with exponential backoff and jitter (first retry >= 5 s),
  so a fleet that loses power together does not reconnect in lockstep.
* A disabled enrollment or a rejected certificate is final: stop instead of retrying.
  Anything else (DPS unreachable during an outage) is retried by the caller indefinitely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from azure.iot.device import exceptions

logger = logging.getLogger("fleet.provisioning")

TRANSIENT_ERRORS: tuple[type[Exception], ...] = (
    exceptions.ConnectionFailedError,
    exceptions.ConnectionDroppedError,
    exceptions.OperationTimeout,
    exceptions.ServiceError,
)


class ProvisioningError(Exception):
    """Provisioning did not produce an assignment."""


class EnrollmentDisabled(ProvisioningError):
    """DPS reports the enrollment as disabled: the device has been revoked."""


class CertificateRejected(ProvisioningError):
    """DPS refused the device certificate; retrying cannot help without a new one."""


FINAL_ERRORS: tuple[type[ProvisioningError], ...] = (EnrollmentDisabled, CertificateRejected)


@dataclass(frozen=True)
class Assignment:
    device_id: str
    assigned_hub: str
    sub_status: str
    provisioned_at: str


class RegistrationClient(Protocol):
    async def register(self) -> Any: ...


RegistrationFactory = Callable[[], RegistrationClient]
Sleep = Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class Backoff:
    base_s: float = 5.0
    cap_s: float = 300.0

    def delay(self, attempt: int, rng: random.Random) -> float:
        """Exponential with jitter in [50%, 100%] of the step, never below ``base_s``."""
        step = min(self.cap_s, self.base_s * (2**attempt))
        return max(self.base_s, step * rng.uniform(0.5, 1.0))


DEFAULT_BACKOFF = Backoff()


class AssignmentStore:
    """Per-device JSON files; writes are atomic so a power cut cannot leave half a file."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def _path(self, device_id: str) -> Path:
        return self._directory / f"{device_id}.json"

    def load(self, device_id: str) -> Assignment | None:
        path = self._path(device_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Assignment(**data)
        except FileNotFoundError:
            return None
        except (ValueError, TypeError) as exc:
            logger.warning("discarding unreadable assignment cache: %s", exc, extra={"device": device_id})
            return None

    def save(self, assignment: Assignment) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._directory, prefix=".assignment-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(assignment), handle, indent=2)
            os.replace(tmp, self._path(assignment.device_id))
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def clear(self, device_id: str) -> None:
        self._path(device_id).unlink(missing_ok=True)


def _reports_disabled(error: BaseException) -> bool:
    """True if DPS answered 'disabled'.

    The SDK does not return that status as a result: it raises ClientError("Unexpected
    failure") caused by a ServiceError naming the status, so the cause chain is inspected.
    """
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if "registration status disabled" in str(current):
            return True
        current = current.__cause__ or current.__context__
    return False


async def _release(client: RegistrationClient) -> None:
    """Close a client whose registration did not complete.

    The SDK closes its connection only after an 'assigned' result and has no public
    shutdown, so the pipeline is shut down here to avoid leaking a connection per attempt.
    """
    pipeline = getattr(client, "_pipeline", None)
    if pipeline is None:
        return
    done = asyncio.get_running_loop().create_future()

    def _callback(error: Exception | None = None) -> None:
        if not done.done():
            done.get_loop().call_soon_threadsafe(done.set_result, error)

    try:
        pipeline.shutdown(callback=_callback)
        await asyncio.wait_for(done, timeout=10)
    except Exception as exc:  # cleanup must never mask the original outcome
        logger.debug("provisioning client shutdown failed: %s", exc)


async def register(
    registration_id: str,
    factory: RegistrationFactory,
    *,
    max_attempts: int = 6,
    backoff: Backoff = DEFAULT_BACKOFF,
    rng: random.Random | None = None,
    sleep: Sleep = asyncio.sleep,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Assignment:
    rng = rng or random.Random()
    for attempt in range(max_attempts):
        client = factory()
        result = None
        try:
            result = await client.register()
        except exceptions.CredentialError as exc:
            await _release(client)
            raise CertificateRejected(f"DPS rejected the device certificate: {exc}") from exc
        except (*TRANSIENT_ERRORS, exceptions.ClientError) as exc:
            await _release(client)
            if _reports_disabled(exc):
                raise EnrollmentDisabled(f"enrollment for {registration_id} is disabled") from exc
            reason = f"{type(exc).__name__}: {exc}"
        else:
            status = getattr(result, "status", None)
            if status == "assigned":
                state = result.registration_state
                return Assignment(
                    device_id=state.device_id,
                    assigned_hub=state.assigned_hub,
                    sub_status=state.sub_status or "",
                    provisioned_at=clock().isoformat(timespec="seconds").replace("+00:00", "Z"),
                )
            await _release(client)
            if status == "disabled":
                raise EnrollmentDisabled(f"enrollment for {registration_id} is disabled")
            reason = f"registration status {status!r}"

        if attempt == max_attempts - 1:
            raise ProvisioningError(f"giving up after {max_attempts} attempts ({reason})")
        delay = backoff.delay(attempt, rng)
        logger.warning(
            "provisioning attempt %d failed (%s); retrying in %.1fs",
            attempt + 1,
            reason,
            delay,
            extra={"device": registration_id},
        )
        await sleep(delay)
    raise ProvisioningError("max_attempts must be at least 1")
