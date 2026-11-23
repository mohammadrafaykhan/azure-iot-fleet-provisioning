import io
import time
from contextlib import contextmanager

import pytest
import requests
import urllib3
from azure.core.credentials import AccessToken
from azure.core.pipeline.transport import RequestsTransport

from service.cli import Services, main
from service.config import ConfigError, ServiceConfig
from service.dps import DpsService, GroupSpec, build_group, build_revocation
from service.hub import HubRegistry
from service.rest import ApiError, Response, RestClient, _error_message, paginate

HUB = "iot-fleet.azure-devices.net"
CONFIG = ServiceConfig(dps_endpoint="https://dps.azure-devices-provisioning.net", hub_hostname=HUB)


class FakeRequester:
    """Replays scripted responses keyed by (method, path) and records every call."""

    def __init__(self, routes=None):
        self.routes = {key: list(value) for key, value in (routes or {}).items()}
        self.calls = []

    def request(self, method, path, *, body=None, headers=None):
        self.calls.append((method, path, body, headers or {}))
        queue = self.routes.get((method, path))
        if not queue:
            return Response(200, {})
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def spec(**overrides):
    values = dict(
        group_id="presses",
        signing_certificate_pem="-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
        iot_hub=HUB,
        tags={"site": "karachi"},
        desired={"telemetryIntervalMs": 5000},
    )
    values.update(overrides)
    return GroupSpec(**values)


def test_group_body_is_x509_with_migration_and_initial_twin():
    body = build_group(spec())
    assert body["attestation"]["type"] == "x509"
    assert body["attestation"]["x509"]["signingCertificates"]["primary"]["certificate"].endswith(
        "CERTIFICATE-----"
    )
    assert body["reprovisionPolicy"] == {"updateHubAssignment": True, "migrateDeviceData": True}
    assert body["iotHubs"] == [HUB]
    assert body["initialTwin"]["tags"] == {"site": "karachi", "enrollmentGroup": "presses"}
    assert body["initialTwin"]["properties"]["desired"] == {"telemetryIntervalMs": 5000}


def test_revocation_is_a_disabled_individual_enrollment():
    body = build_revocation("press-03", "PEM")
    assert body["provisioningStatus"] == "disabled"
    assert body["attestation"]["x509"]["clientCertificates"]["primary"]["certificate"] == "PEM"


def test_put_group_creates_when_missing():
    rest = FakeRequester({("GET", "/enrollmentGroups/presses"): [ApiError(404, "not found")]})
    DpsService(rest).put_group(spec())
    method, path, body, headers = rest.calls[-1]
    assert (method, path) == ("PUT", "/enrollmentGroups/presses")
    assert "If-Match" not in headers and "etag" not in body


def test_put_group_updates_with_etag():
    rest = FakeRequester({("GET", "/enrollmentGroups/presses"): [Response(200, {"etag": '"7"'})]})
    DpsService(rest).put_group(spec())
    _, _, body, headers = rest.calls[-1]
    assert headers["If-Match"] == '"7"' and body["etag"] == '"7"'


def test_put_group_surfaces_other_errors():
    rest = FakeRequester({("GET", "/enrollmentGroups/presses"): [ApiError(403, "forbidden")]})
    with pytest.raises(ApiError):
        DpsService(rest).put_group(spec())


def test_disable_group_round_trips_with_etag():
    group = {"enrollmentGroupId": "presses", "provisioningStatus": "enabled", "etag": '"3"'}
    rest = FakeRequester({("GET", "/enrollmentGroups/presses"): [Response(200, group)]})
    DpsService(rest).set_group_enabled("presses", False)
    _, _, body, headers = rest.calls[-1]
    assert body["provisioningStatus"] == "disabled" and headers["If-Match"] == '"3"'


def test_ids_are_url_encoded():
    rest = FakeRequester()
    DpsService(rest).delete_registration("line:1/press")
    assert rest.calls[0][1] == "/registrations/line%3A1%2Fpress"


def test_reinstate_reports_missing_revocation():
    rest = FakeRequester({("DELETE", "/enrollments/press-03"): [ApiError(404, "none")]})
    assert DpsService(rest).reinstate("press-03") is False


def test_hub_disable_uses_quoted_device_etag():
    device = {"deviceId": "press-03", "etag": "MTA=", "status": "enabled"}
    rest = FakeRequester(
        {
            ("GET", "/devices/press-03"): [Response(200, device)],
            ("PUT", "/devices/press-03"): [Response(200, {"status": "disabled"})],
        }
    )
    assert HubRegistry(rest).set_enabled("press-03", False, "compromised")["status"] == "disabled"
    _, _, body, headers = rest.calls[-1]
    assert headers["If-Match"] == '"MTA="'
    assert body["status"] == "disabled" and body["statusReason"] == "compromised"


def test_hub_query_filters_by_group_and_rejects_injection():
    rest = FakeRequester()
    HubRegistry(rest).list_devices("presses")
    assert rest.calls[0][2] == {"query": "SELECT * FROM devices WHERE tags.enrollmentGroup = 'presses'"}
    with pytest.raises(ValueError):
        HubRegistry(rest).list_devices("x' OR 1=1 --")


def test_hub_devices_take_connection_state_from_the_identity_not_the_query():
    twin = {"deviceId": "press-01", "status": "enabled", "connectionState": "Disconnected", "tags": {}}
    rest = FakeRequester(
        {
            ("POST", "/devices/query"): [Response(200, [twin, {**twin, "deviceId": "gone"}])],
            ("GET", "/devices/press-01"): [
                Response(200, {"connectionState": "Connected", "connectionStateUpdatedTime": "T"})
            ],
            ("GET", "/devices/gone"): [ApiError(404, "not found")],
        }
    )
    first, second = HubRegistry(rest).list_devices("presses")
    assert first["connectionState"] == "Connected" and first["connectionStateUpdatedTime"] == "T"
    assert second["connectionState"] == "Disconnected"


def test_paginate_follows_continuation_until_limit():
    rest = FakeRequester(
        {
            ("POST", "/q"): [
                Response(200, [{"n": 1}, {"n": 2}], {"x-ms-continuation": "page2"}),
                Response(200, [{"n": 3}], {}),
            ]
        }
    )
    assert [item["n"] for item in paginate(rest, "/q", {}, 2, 10)] == [1, 2, 3]
    assert rest.calls[1][3]["x-ms-continuation"] == "page2"


def test_error_message_prefers_service_message():
    assert _error_message({"Message": "ErrorCode:DeviceNotFound;device not found\nTracking"}, "x") == (
        "ErrorCode:DeviceNotFound;device not found"
    )
    assert _error_message("plain", "fallback") == "fallback"


class StaticToken:
    def get_token(self, *scopes, **kwargs):
        return AccessToken("token", int(time.time()) + 3600)


class RecordingAdapter(requests.adapters.BaseAdapter):
    """Stands in for the network under azure-core's real RequestsTransport."""

    def __init__(self, status, body):
        super().__init__()
        self.status, self.body, self.sent = status, body, []

    def send(self, request, **kwargs):
        self.sent.append(request)
        headers = {"Content-Type": "application/json", "Content-Length": str(len(self.body))}
        raw = requests.Response()
        raw.status_code, raw.url, raw.request = self.status, request.url, request
        raw.headers.update(headers)
        raw.raw = urllib3.HTTPResponse(
            body=io.BytesIO(self.body), status=self.status, headers=headers, preload_content=False
        )
        return raw

    def close(self):
        pass


def recording_transport(status=200, body=b'{"ok": true}'):
    adapter = RecordingAdapter(status, body)
    session = requests.Session()
    session.mount("https://", adapter)
    return RequestsTransport(session=session, session_owner=False), adapter


def test_rest_client_sends_authenticated_https_requests_to_the_endpoint():
    transport, adapter = recording_transport()
    with RestClient(
        "https://dps.example.net", StaticToken(), "scope/.default", "2021-10-01", transport=transport
    ) as client:
        response = client.request(
            "PUT", "/enrollmentGroups/presses", body={"a": 1}, headers={"If-Match": "e"}
        )
    sent = adapter.sent[0]
    assert sent.url == "https://dps.example.net/enrollmentGroups/presses?api-version=2021-10-01"
    assert sent.headers["Authorization"] == "Bearer token"
    assert sent.headers["If-Match"] == "e"
    assert response.status == 200 and response.body == {"ok": True}


def test_rest_client_raises_api_error_with_the_service_message():
    transport, _ = recording_transport(status=404, body=b'{"message": "Enrollment not found"}')
    client = RestClient("https://dps.example.net", StaticToken(), "s", "v", transport=transport)
    with client, pytest.raises(ApiError, match="404: Enrollment not found"):
        client.request("GET", "/enrollments/x")


# --- CLI ---------------------------------------------------------------------------


@pytest.fixture
def certs(tmp_path):
    from pki.authority import Pki

    pki = Pki(tmp_path)
    pki.create_root("Root")
    pki.create_intermediate("devices", "Fleet Devices CA")
    pki.issue_device("press-03", "devices")
    return pki.layout


def run_cli(argv, dps=None, hub=None):
    dps, hub = dps or FakeRequester(), hub or FakeRequester()

    @contextmanager
    def factory(config):
        yield Services(DpsService(dps), HubRegistry(hub), config.hub_hostname)

    return main(argv, services_factory=factory, config_loader=lambda: CONFIG), dps, hub


def test_cli_group_create_sends_intermediate(certs, capsys):
    code, dps, _ = run_cli(
        [
            "group",
            "create",
            "presses",
            "--ca",
            str(certs.intermediate_cert("devices")),
            "--tag",
            "site=karachi",
        ]
    )
    assert code == 0
    put = next(call for call in dps.calls if call[0] == "PUT")
    assert put[2]["initialTwin"]["tags"]["site"] == "karachi"
    assert (
        "BEGIN CERTIFICATE" in put[2]["attestation"]["x509"]["signingCertificates"]["primary"]["certificate"]
    )


def test_cli_group_create_rejects_a_leaf_certificate(certs, capsys):
    code, _, _ = run_cli(["group", "create", "presses", "--ca", str(certs.device_cert("press-03"))])
    assert code == 2 and "not a CA" in capsys.readouterr().err


def test_cli_revoke_blocks_dps_and_hub(certs, capsys):
    hub = FakeRequester(
        {
            ("GET", "/devices/press-03"): [Response(200, {"etag": "1", "status": "enabled"})],
            ("PUT", "/devices/press-03"): [Response(200, {"status": "disabled"})],
        }
    )
    dps = FakeRequester(
        {
            ("GET", "/enrollments/press-03"): [ApiError(404, "none")],
            ("PUT", "/enrollments/press-03"): [Response(200, {"provisioningStatus": "disabled"})],
        }
    )
    code, _, _ = run_cli(["revoke", "press-03", "--cert", str(certs.device_cert("press-03"))], dps, hub)
    assert code == 0
    assert '"hubStatus": "disabled"' in capsys.readouterr().out


def test_cli_revoke_refuses_another_devices_certificate(certs, capsys):
    code, dps, _ = run_cli(["revoke", "press-04", "--cert", str(certs.device_cert("press-03"))])
    assert code == 2 and dps.calls == []
    assert "belongs to 'press-03'" in capsys.readouterr().err


def test_cli_revoke_tolerates_device_not_yet_in_hub(certs, capsys):
    hub = FakeRequester({("GET", "/devices/press-03"): [ApiError(404, "not found")]})
    code, _, _ = run_cli(["revoke", "press-03", "--cert", str(certs.device_cert("press-03"))], hub=hub)
    assert code == 0 and "not registered in hub" in capsys.readouterr().out


def test_cli_api_error_exits_1(capsys):
    dps = FakeRequester({("GET", "/enrollmentGroups/nope"): [ApiError(404, "Enrollment not found")]})
    code, _, _ = run_cli(["group", "show", "nope"], dps)
    assert code == 1 and "HTTP 404" in capsys.readouterr().err


def test_cli_config_error_exits_2(capsys):
    def broken():
        raise ConfigError("DPS_SERVICE_HOSTNAME is not set")

    assert main(["group", "list"], config_loader=broken) == 2
