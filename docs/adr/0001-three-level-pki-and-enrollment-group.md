# ADR 0001: Three-level X.509 PKI with an intermediate-based enrollment group

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Devices must join the fleet without anyone registering them one by one. DPS supports
symmetric-key, TPM, and X.509 attestation; X.509 enrollment groups let any device whose
certificate chain contains a trusted CA provision itself.

## Decision

- **Root CA → Devices CA (intermediate) → device**, all ECDSA P-256 with SHA-256.
  Path lengths 1 and 0 stop a device certificate, or the intermediate, from signing further CAs.
- The **root is the verified CA** in DPS and IoT Hub; the **enrollment group names the
  intermediate** as its signing certificate, the more common setup Microsoft describes.
  A second product line or site gets its own intermediate and group under the same root.
- **CN = device ID = registration ID**, validated against DPS rules (≤ 64 characters,
  `A-Z a-z 0-9 - . _ :`) at issue time rather than failing at provisioning time.
- Device certificates carry `clientAuth` EKU, `digitalSignature` only, and a one-year validity
  capped at the issuer's expiry. Devices present **leaf → intermediate → root**.
- The root CA is uploaded as **verified** by Bicep (`isVerified: true`). This is acceptable because
  the same operator owns the CA and the subscription; it skips the proof-of-possession round trip.

## Consequences

- Adding a device is issuing a certificate; nothing changes in Azure.
- The root key is needed only to issue intermediates and should stay offline. Losing the
  intermediate key requires disabling the group and re-issuing the fleet under a new intermediate.
