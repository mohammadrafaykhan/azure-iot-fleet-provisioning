import asyncio
import json
from types import SimpleNamespace

import pytest
from azure.iot.device import exceptions

from device.app import CertificateInfo, FleetDevice
from device.provisioning import (
    Assignment,
    AssignmentStore,
    Backoff,
    CertificateRejected,
    EnrollmentDisabled,
    ProvisioningError,
)
from pki.authority import Pki

HUB = "hub.azure-devices.net"
CERT = CertificateInfo(thumbprint="AB" * 32, issuer="Fleet Devices CA", not_after="2027-11-18T00:00:00Z")


def assignment(device_id="press-01", hub=HUB):
    return Assignment(device_id, hub, "initialAssignment", "2026-11-18T12:00:00Z")


class FakeHub:
    def __init__(self, *, connect_error=None, twin=None, send_error=None, on_send=None):
        self.connect_error = connect_error
        self.send_error = send_error
        self.twin = twin or {"desired": {"$version": 1}, "reported": {}}
        self.on_send = on_send
        self.reported, self.sent, self.responses = [], [], []
        self.shut_down = False
        self.on_twin_desired_properties_patch_received = None
        self.on_method_request_received = None

    async def connect(self):
        if self.connect_error:
            raise self.connect_error

    async def shutdown(self):
        self.shut_down = True

    async def get_twin(self):
        return self.twin

    async def patch_twin_reported_properties(self, patch):
        self.reported.append(patch)

    async def send_message(self, message):
        if self.send_error:
            raise self.send_error
        self.sent.append(json.loads(message.data))
        if self.on_send:
            await self.on_send(self)

    async def send_method_response(self, response):
        self.responses.append(response)


class Harness:
    def __init__(self, tmp_path, hubs, provisioned=None):
        self.stop = asyncio.Event()
        self.store = AssignmentStore(tmp_path)
        self.hubs = list(hubs)
        self.used = []
        self.provisioned = list(provisioned or [])
        self.provision_calls = 0
        self.device = FleetDevice(
            "press-01",
            store=self.store,
            provision=self._provision,
            hub_factory=self._hub,
            certificate=CERT,
            backoff=Backoff(base_s=0.001, cap_s=0.001),
        )

    async def _provision(self):
        self.provision_calls += 1
        outcome = self.provisioned.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def _hub(self, assignment):
        hub = self.hubs.pop(0)
        hub.assignment = assignment
        self.used.append(hub)
        return hub

    async def stop_after_send(self, hub):
        self.stop.set()

    async def run(self):
        await asyncio.wait_for(self.device.run(self.stop), timeout=5)


async def test_cached_assignment_skips_dps(tmp_path):
    h = Harness(tmp_path, [])
    h.hubs.append(FakeHub(on_send=h.stop_after_send))
    h.store.save(assignment())
    await h.run()
    assert h.provision_calls == 0
    hub = h.used[0]
    assert hub.assignment.assigned_hub == HUB
    assert hub.sent[0]["deviceId"] == "press-01" and hub.sent[0]["sequence"] == 1
    assert hub.shut_down


async def test_first_boot_provisions_and_caches(tmp_path):
    h = Harness(tmp_path, [], provisioned=[assignment()])
    h.hubs.append(FakeHub(on_send=h.stop_after_send))
    await h.run()
    assert h.provision_calls == 1
    assert h.store.load("press-01") == assignment()


async def test_startup_report_carries_provisioning_certificate_and_initial_twin(tmp_path):
    h = Harness(tmp_path, [], provisioned=[assignment()])
    twin = {"desired": {"$version": 2, "telemetryIntervalMs": 2000}, "reported": {}}
    h.hubs.append(FakeHub(twin=twin, on_send=h.stop_after_send))
    await h.run()
    report = h.used[0].reported[0]
    assert report["provisioning"]["assignedHub"] == HUB
    assert report["certificate"]["thumbprint"] == CERT.thumbprint
    assert report["telemetryIntervalMs"] == {"value": 2000, "ac": 200, "av": 2, "ad": "applied"}
    assert h.device.interval_ms == 2000


async def test_hub_rejecting_identity_triggers_reprovision(tmp_path):
    h = Harness(tmp_path, [], provisioned=[assignment(hub="new-hub.azure-devices.net")])
    h.store.save(assignment(hub="old-hub.azure-devices.net"))
    h.hubs += [
        FakeHub(connect_error=exceptions.CredentialError("unauthorized")),
        FakeHub(on_send=h.stop_after_send),
    ]
    await h.run()
    assert h.provision_calls == 1
    assert [hub.assignment.assigned_hub for hub in h.used] == [
        "old-hub.azure-devices.net",
        "new-hub.azure-devices.net",
    ]
    assert all(hub.shut_down for hub in h.used)


async def test_revoked_device_stops(tmp_path):
    h = Harness(tmp_path, [], provisioned=[EnrollmentDisabled("disabled")])
    h.store.save(assignment())
    h.hubs.append(FakeHub(connect_error=exceptions.CredentialError("device disabled")))
    with pytest.raises(EnrollmentDisabled):
        await h.run()
    assert h.store.load("press-01") is None


async def test_provisioning_outage_is_retried_not_fatal(tmp_path):
    outage = ProvisioningError("giving up after 6 attempts (ConnectionFailedError: dns)")
    h = Harness(tmp_path, [], provisioned=[outage, outage, assignment()])
    h.hubs.append(FakeHub(on_send=h.stop_after_send))
    await h.run()
    assert h.provision_calls == 3 and h.store.load("press-01") == assignment()


async def test_rejected_certificate_stops_the_device(tmp_path):
    h = Harness(tmp_path, [], provisioned=[CertificateRejected("expired")])
    with pytest.raises(CertificateRejected):
        await h.run()
    assert h.provision_calls == 1


async def test_repeated_connect_failures_reprovision(tmp_path):
    h = Harness(tmp_path, [], provisioned=[assignment()])
    h.store.save(assignment())
    h.hubs += [FakeHub(connect_error=exceptions.ConnectionFailedError("down")) for _ in range(3)]
    h.hubs.append(FakeHub(on_send=h.stop_after_send))
    await h.run()
    assert h.provision_calls == 1


@pytest.mark.parametrize(
    "error",
    [
        exceptions.ConnectionDroppedError("gone"),
        # seen live: with connection_retry=False a drop cancels the in-flight send
        exceptions.OperationCancelled("Operation was cancelled before completion"),
        # seen live: a hub over its daily quota answers 403, raised as a generic ClientError
        exceptions.ClientError("Unexpected failure"),
    ],
)
async def test_dropped_connection_reconnects_with_cached_assignment(tmp_path, error):
    h = Harness(tmp_path, [])
    h.store.save(assignment())
    h.hubs += [
        FakeHub(send_error=error),
        FakeHub(on_send=h.stop_after_send),
    ]
    await h.run()
    assert h.provision_calls == 0 and len(h.used) == 2


async def test_backoff_grows_across_failed_sessions_and_resets_after_delivery(tmp_path):
    h = Harness(tmp_path, [])
    h.store.save(assignment())
    h.device._machine.state.interval_ms = 1
    attempts = []

    async def pause(attempt, stop, reason):
        attempts.append(attempt)

    async def fail_next_send(hub):
        hub.send_error = exceptions.ConnectionDroppedError("gone")

    h.device._pause = pause
    drop = exceptions.ConnectionDroppedError("gone")
    h.hubs += [
        FakeHub(send_error=drop),
        FakeHub(send_error=drop),
        FakeHub(on_send=fail_next_send),
        FakeHub(send_error=drop),
        FakeHub(on_send=h.stop_after_send),
    ]
    await h.run()
    assert attempts == [1, 2, 1, 2]


async def test_reprovision_method_clears_cache_and_registers_again(tmp_path):
    h = Harness(tmp_path, [], provisioned=[assignment(hub="hub-2.azure-devices.net")])
    h.store.save(assignment())

    async def request_reprovision(hub):
        await h.device.on_method_request(SimpleNamespace(name="Reprovision", request_id="1", payload=None))

    h.hubs += [FakeHub(on_send=request_reprovision), FakeHub(on_send=h.stop_after_send)]
    await h.run()
    assert h.used[0].responses[0].status == 200
    assert h.provision_calls == 1
    assert h.store.load("press-01").assigned_hub == "hub-2.azure-devices.net"


async def test_unknown_method_returns_404(tmp_path):
    h = Harness(tmp_path, [])
    h.store.save(assignment())

    async def call_unknown(hub):
        await h.device.on_method_request(SimpleNamespace(name="SelfDestruct", request_id="1", payload=None))
        h.stop.set()

    h.hubs.append(FakeHub(on_send=call_unknown))
    await h.run()
    assert h.used[0].responses[0].status == 404


async def test_invalid_desired_interval_is_rejected(tmp_path):
    h = Harness(tmp_path, [])
    h.store.save(assignment())

    async def patch(hub):
        await h.device.on_desired_patch({"telemetryIntervalMs": 100, "$version": 4})
        h.stop.set()

    h.hubs.append(FakeHub(on_send=patch))
    await h.run()
    ack = h.used[0].reported[-1]["telemetryIntervalMs"]
    assert ack["ac"] == 400 and ack["av"] == 4 and ack["value"] == 60_000


def test_certificate_info_from_chain(tmp_path):
    pki = Pki(tmp_path)
    pki.create_root("Root")
    pki.create_intermediate("devices", "Fleet Devices CA")
    info = CertificateInfo.from_pem(pki.issue_device("press-01", "devices").read_bytes())
    assert info.issuer == "Fleet Devices CA"
    assert len(info.thumbprint) == 64 and info.not_after.endswith("Z")


async def test_one_device_crashing_does_not_stop_the_fleet(caplog):
    from device.__main__ import _supervise

    class Crashing:
        device_id = "press-03"

        async def run(self, stop):
            raise RuntimeError("boom")

    class Healthy:
        device_id = "press-01"
        ran = False

        async def run(self, stop):
            await asyncio.sleep(0)
            Healthy.ran = True

    stop = asyncio.Event()
    await asyncio.gather(_supervise(Crashing(), stop, 0), _supervise(Healthy(), stop, 0))
    assert Healthy.ran
    assert "device stopped unexpectedly" in caplog.text
