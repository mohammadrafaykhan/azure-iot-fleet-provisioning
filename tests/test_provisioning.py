import random
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from azure.iot.device import exceptions

from device.provisioning import (
    Assignment,
    AssignmentStore,
    Backoff,
    CertificateRejected,
    EnrollmentDisabled,
    ProvisioningError,
    _release,
    register,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def assigned(device_id="press-01", hub="hub.azure-devices.net", sub_status="initialAssignment"):
    state = SimpleNamespace(device_id=device_id, assigned_hub=hub, sub_status=sub_status)
    return SimpleNamespace(status="assigned", registration_state=state)


class FakeRegistration:
    def __init__(self, outcome):
        self.outcome = outcome

    async def register(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class Factory:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.created = 0

    def __call__(self):
        self.created += 1
        return FakeRegistration(self.outcomes.pop(0))


class Sleeps:
    def __init__(self):
        self.calls = []

    async def __call__(self, seconds):
        self.calls.append(seconds)


async def test_assigned_on_first_attempt():
    sleeps = Sleeps()
    result = await register("press-01", Factory(assigned()), sleep=sleeps, clock=lambda: NOW)
    assert result == Assignment(
        "press-01", "hub.azure-devices.net", "initialAssignment", "2026-11-18T12:00:00Z"
    )
    assert sleeps.calls == []


async def test_transient_errors_retry_with_backoff_of_at_least_five_seconds():
    sleeps = Sleeps()
    factory = Factory(
        exceptions.ConnectionFailedError("dns"),
        SimpleNamespace(status="failed", registration_state=None),
        assigned(),
    )
    result = await register("press-01", factory, sleep=sleeps, rng=random.Random(1))
    assert result.device_id == "press-01"
    assert factory.created == 3
    assert len(sleeps.calls) == 2
    assert all(delay >= 5 for delay in sleeps.calls)


async def test_disabled_enrollment_is_final():
    sleeps = Sleeps()
    factory = Factory(SimpleNamespace(status="disabled", registration_state=None), assigned())
    with pytest.raises(EnrollmentDisabled):
        await register("press-03", factory, sleep=sleeps)
    assert factory.created == 1 and sleeps.calls == []


def sdk_disabled_error():
    """What azure-iot-device 2.x raises when DPS answers 'disabled' (seen live)."""
    cause = exceptions.ServiceError(
        "Query Status Operation encountered an invalid registration status disabled with a status code of 200"
    )
    error = exceptions.ClientError("Unexpected failure")
    error.__cause__ = cause
    return error


async def test_disabled_enrollment_raised_by_the_sdk_is_final():
    sleeps = Sleeps()
    factory = Factory(sdk_disabled_error(), assigned())
    with pytest.raises(EnrollmentDisabled):
        await register("press-03", factory, sleep=sleeps)
    assert factory.created == 1 and sleeps.calls == []


async def test_other_client_errors_are_retried():
    factory = Factory(exceptions.ClientError("Unexpected failure"), assigned())
    sleeps = Sleeps()
    assert (await register("press-01", factory, sleep=sleeps)).device_id == "press-01"
    assert factory.created == 2 and len(sleeps.calls) == 1


async def test_rejected_certificate_is_not_retried():
    factory = Factory(exceptions.CredentialError("bad chain"), assigned())
    with pytest.raises(CertificateRejected, match="rejected the device certificate"):
        await register("press-01", factory, sleep=Sleeps())
    assert factory.created == 1


async def test_gives_up_after_max_attempts():
    factory = Factory(*[exceptions.OperationTimeout("slow")] * 3)
    with pytest.raises(ProvisioningError, match="after 3 attempts"):
        await register("press-01", factory, max_attempts=3, sleep=Sleeps())


def test_backoff_grows_and_is_capped():
    rng = random.Random(7)
    backoff = Backoff(base_s=5, cap_s=60)
    delays = [backoff.delay(attempt, rng) for attempt in range(8)]
    assert all(5 <= d <= 60 for d in delays)
    assert delays[-1] >= 30


async def test_release_shuts_down_an_unfinished_pipeline():
    calls = []

    class Pipeline:
        def shutdown(self, callback):
            calls.append("shutdown")
            callback(error=None)

    await _release(SimpleNamespace(_pipeline=Pipeline()))
    assert calls == ["shutdown"]


async def test_release_never_raises():
    class Pipeline:
        def shutdown(self, callback):
            raise RuntimeError("already stopped")

    await _release(SimpleNamespace(_pipeline=Pipeline()))


def test_store_round_trip_and_clear(tmp_path):
    store = AssignmentStore(tmp_path / "state")
    assignment = Assignment("press-01", "hub.azure-devices.net", "initialAssignment", "2026-11-18T12:00:00Z")
    assert store.load("press-01") is None
    store.save(assignment)
    assert store.load("press-01") == assignment
    assert not list((tmp_path / "state").glob("*.tmp"))
    store.clear("press-01")
    assert store.load("press-01") is None
    store.clear("press-01")


def test_corrupt_cache_is_discarded(tmp_path):
    (tmp_path / "press-01.json").write_text("{not json", encoding="utf-8")
    assert AssignmentStore(tmp_path).load("press-01") is None
    (tmp_path / "press-02.json").write_text('{"unexpected": 1}', encoding="utf-8")
    assert AssignmentStore(tmp_path).load("press-02") is None
