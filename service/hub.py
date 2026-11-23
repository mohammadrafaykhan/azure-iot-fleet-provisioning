"""IoT Hub registry operations over REST: fleet queries and enabling or disabling devices."""

from __future__ import annotations

import re

from service.rest import ApiError, Requester, paginate

HUB_SCOPE = "https://iothubs.azure.net/.default"
HUB_API_VERSION = "2021-04-12"

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9\-._:]{1,128}$")


def _quote(segment: str) -> str:
    from urllib.parse import quote

    return quote(segment, safe="")


def summarize_twin(twin: dict, identity: dict | None = None) -> dict:
    """Twin fields plus connection state from the device identity (query results lag behind it)."""
    reported = (twin.get("properties") or {}).get("reported") or {}
    interval = reported.get("telemetryIntervalMs")
    identity = identity or {}
    return {
        "deviceId": twin.get("deviceId"),
        "status": twin.get("status"),
        "connectionState": identity.get("connectionState", twin.get("connectionState")),
        "connectionStateUpdatedTime": identity.get("connectionStateUpdatedTime"),
        "authentication": twin.get("authenticationType"),
        "tags": twin.get("tags") or {},
        "provisioning": reported.get("provisioning"),
        "certificate": reported.get("certificate"),
        "telemetryIntervalMs": interval.get("value") if isinstance(interval, dict) else interval,
    }


class HubRegistry:
    def __init__(self, requester: Requester) -> None:
        self._rest = requester

    def list_devices(self, group_id: str | None = None, limit: int = 100) -> list[dict]:
        """Query twins, then read each identity for its live connection state (one GET per device)."""
        query = "SELECT * FROM devices"
        if group_id:
            if not _SAFE_VALUE.fullmatch(group_id):
                raise ValueError(f"invalid enrollment group id {group_id!r}")
            query += f" WHERE tags.enrollmentGroup = '{group_id}'"
        twins = paginate(self._rest, "/devices/query", {"query": query}, 100, limit)
        return [summarize_twin(twin, self._identity(twin.get("deviceId"))) for twin in twins]

    def _identity(self, device_id: str | None) -> dict | None:
        if not device_id:
            return None
        try:
            return self._rest.request("GET", f"/devices/{_quote(device_id)}").body
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def set_enabled(self, device_id: str, enabled: bool, reason: str = "") -> dict:
        path = f"/devices/{_quote(device_id)}"
        device = self._rest.request("GET", path).body
        device["status"] = "enabled" if enabled else "disabled"
        device["statusReason"] = reason[:128] if reason else None
        response = self._rest.request("PUT", path, body=device, headers={"If-Match": f'"{device["etag"]}"'})
        return {"deviceId": device_id, "status": response.body.get("status")}
