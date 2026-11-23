# ADR 0004: Revocation and certificate rotation

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

With chain-based trust, the cloud does not hold a per-device credential to delete, and
neither DPS nor IoT Hub consults CRLs or OCSP. Revocation and rotation must work with what
the services provide.

## Decision

- **Revoke one device** (`fleetctl revoke`): create a **disabled individual enrollment** for the
  device's certificate, which DPS evaluates before the group, and **disable the device in IoT
  Hub**, which drops its connection. On reconnect the hub refuses it; on re-provision DPS
  returns *disabled* and the device stops. `fleetctl reinstate` reverses both.
- **Compromised intermediate:** disable the enrollment group, issue a new intermediate and
  group, re-issue device certificates.
- **Rotate a device certificate** (`python -m pki device <id> --rotate`): new key pair, same CN,
  old identity archived. The new certificate chains to the same CA, so DPS accepts it with no
  operator change. The hub, however, pins the leaf thumbprint DPS registered (`selfSigned`
  authentication), so it rejects the new certificate; the device treats that rejection as a
  signal to re-provision, and DPS updates the hub identity. Verified live: rejection to
  connected in 4 seconds, twin kept.

## Consequences

- Revocation is two API calls. Disabling the hub device drops the live connection within
  seconds; the device's re-provision attempt is then answered *disabled* and it stops.
- The Python device SDK (azure-iot-device 2.x) does not return the *disabled* status as a
  result: it raises `ClientError("Unexpected failure")` caused by a `ServiceError` naming the
  status, so the device inspects the cause chain to recognise a revocation.
- Rotation costs one DPS registration per device, which is why re-provisioning is driven by
  the hub's rejection rather than done on every boot.
- The hub device stays disabled and DPS matches individual enrollments by registration ID, so
  a re-issued certificate for a revoked device does not bring it back; reinstating is explicit.
