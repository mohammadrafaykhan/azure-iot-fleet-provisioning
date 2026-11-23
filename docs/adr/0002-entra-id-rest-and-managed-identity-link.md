# ADR 0002: Entra ID end to end, REST over beta SDKs, managed-identity hub link

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

The operator tool manages DPS enrollments and IoT Hub devices. In November 2026 the Python
options were `azure-iot-deviceprovisioning` (1.0.0b1, beta since June 2023),
`azure-iothub-provisioningserviceclient` (last released 2018), and `azure-iot-hub`, which
depends on the deprecated `uamqp` (see the device-control project's ADR 0002).
DPS links to IoT hubs either by connection string or, in the 2026-11-01 API, by managed identity.

## Decision

- `fleetctl` calls the **documented REST APIs** (DPS `2021-10-01`, IoT Hub `2021-04-12`) through
  **azure-core**, which provides Entra ID token refresh, retries that honour `Retry-After`, and
  request logging. One small adapter per service keeps the surface easy to replace.
- **DPS `disableLocalAuth: true`**: its shared access policies cannot be used, so every service
  call needs an Entra ID token and the *Device Provisioning Service Data Contributor* role.
- DPS reaches the hub with its **system-assigned managed identity** holding *IoT Hub Data
  Contributor*; no hub connection string is stored anywhere. Because the identity exists only
  after DPS is created, the link is applied as a second update of DPS in `dps-link.bicep`.

## Consequences

- No secrets in code, `.env`, deployment outputs, or git; access is revocable per person in RBAC.
- REST payloads are maintained here rather than by an SDK, so they are covered by unit tests.
- The hub keeps shared access policies enabled because DPS requires that for linked hubs;
  device SAS and module SAS stay disabled, so devices still have only X.509.
