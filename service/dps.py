"""DPS service operations: enrollment groups, individual enrollments, registration records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from service.rest import ApiError, Requester, paginate

DPS_SCOPE = "https://azure-devices-provisioning.net/.default"
DPS_API_VERSION = "2021-10-01"


@dataclass(frozen=True)
class GroupSpec:
    group_id: str
    signing_certificate_pem: str
    iot_hub: str
    tags: dict[str, str]
    desired: dict[str, Any]


def _quote(segment: str) -> str:
    from urllib.parse import quote

    return quote(segment, safe="")


def _if_match(etag: str | None) -> dict[str, str]:
    return {"If-Match": etag} if etag else {}


def build_group(spec: GroupSpec) -> dict:
    """An X.509 enrollment group: any device whose chain includes the signing CA may join."""
    return {
        "enrollmentGroupId": spec.group_id,
        "attestation": {
            "type": "x509",
            "x509": {
                "signingCertificates": {"primary": {"certificate": spec.signing_certificate_pem.strip()}}
            },
        },
        "provisioningStatus": "enabled",
        "allocationPolicy": "hashed",
        "iotHubs": [spec.iot_hub],
        "reprovisionPolicy": {"updateHubAssignment": True, "migrateDeviceData": True},
        "capabilities": {"iotEdge": False},
        "initialTwin": {
            "tags": {**spec.tags, "enrollmentGroup": spec.group_id},
            "properties": {"desired": spec.desired},
        },
    }


def build_revocation(registration_id: str, device_certificate_pem: str) -> dict:
    """A disabled individual enrollment for one certificate; it takes precedence over its group."""
    return {
        "registrationId": registration_id,
        "attestation": {
            "type": "x509",
            "x509": {"clientCertificates": {"primary": {"certificate": device_certificate_pem.strip()}}},
        },
        "provisioningStatus": "disabled",
    }


def summarize_group(group: dict) -> dict:
    x509 = group.get("attestation", {}).get("x509", {}) or {}
    info = ((x509.get("signingCertificates") or {}).get("primary") or {}).get("info") or {}
    return {
        "groupId": group.get("enrollmentGroupId"),
        "status": group.get("provisioningStatus"),
        "allocationPolicy": group.get("allocationPolicy"),
        "iotHubs": group.get("iotHubs"),
        "signingCertificate": {
            "subject": info.get("subjectName"),
            "thumbprint": info.get("sha256Thumbprint"),
            "notAfter": info.get("notAfterUtc"),
        },
        "reprovisionPolicy": group.get("reprovisionPolicy"),
        "initialTwin": group.get("initialTwin"),
        "etag": group.get("etag"),
    }


def summarize_registration(record: dict) -> dict:
    return {
        "registrationId": record.get("registrationId"),
        "deviceId": record.get("deviceId"),
        "status": record.get("status"),
        "subStatus": record.get("substatus"),
        "assignedHub": record.get("assignedHub"),
        "lastUpdated": record.get("lastUpdatedDateTimeUtc"),
        **({"error": record.get("errorMessage")} if record.get("errorMessage") else {}),
    }


class DpsService:
    def __init__(self, requester: Requester) -> None:
        self._rest = requester

    def put_group(self, spec: GroupSpec) -> dict:
        try:
            etag = self._rest.request("GET", f"/enrollmentGroups/{_quote(spec.group_id)}").body.get("etag")
        except ApiError as exc:
            if exc.status != 404:
                raise
            etag = None
        body = build_group(spec)
        if etag:
            body["etag"] = etag
        response = self._rest.request(
            "PUT", f"/enrollmentGroups/{_quote(spec.group_id)}", body=body, headers=_if_match(etag)
        )
        return summarize_group(response.body)

    def get_group(self, group_id: str) -> dict:
        return summarize_group(self._rest.request("GET", f"/enrollmentGroups/{_quote(group_id)}").body)

    def list_groups(self, limit: int = 100) -> list[dict]:
        groups = paginate(self._rest, "/enrollmentGroups/query", {"query": "*"}, 100, limit)
        return [summarize_group(group) for group in groups]

    def set_group_enabled(self, group_id: str, enabled: bool) -> dict:
        path = f"/enrollmentGroups/{_quote(group_id)}"
        group = self._rest.request("GET", path).body
        group["provisioningStatus"] = "enabled" if enabled else "disabled"
        response = self._rest.request("PUT", path, body=group, headers=_if_match(group.get("etag")))
        return summarize_group(response.body)

    def delete_group(self, group_id: str) -> None:
        self._rest.request("DELETE", f"/enrollmentGroups/{_quote(group_id)}")

    def list_registrations(self, group_id: str, limit: int = 1000) -> list[dict]:
        records = paginate(self._rest, f"/registrations/{_quote(group_id)}/query", {}, 100, limit)
        return [summarize_registration(record) for record in records]

    def delete_registration(self, registration_id: str) -> None:
        self._rest.request("DELETE", f"/registrations/{_quote(registration_id)}")

    def revoke(self, registration_id: str, device_certificate_pem: str) -> dict:
        path = f"/enrollments/{_quote(registration_id)}"
        body = build_revocation(registration_id, device_certificate_pem)
        try:
            existing = self._rest.request("GET", path).body
        except ApiError as exc:
            if exc.status != 404:
                raise
            existing = None
        headers = _if_match(existing.get("etag")) if existing else {}
        if existing:
            body["etag"] = existing.get("etag")
        response = self._rest.request("PUT", path, body=body, headers=headers)
        return {"registrationId": registration_id, "status": response.body.get("provisioningStatus")}

    def reinstate(self, registration_id: str) -> bool:
        """Remove the device's disabled individual enrollment; returns False if there was none."""
        try:
            self._rest.request("DELETE", f"/enrollments/{_quote(registration_id)}")
        except ApiError as exc:
            if exc.status == 404:
                return False
            raise
        return True
