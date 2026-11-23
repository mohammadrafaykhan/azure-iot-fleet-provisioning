# ADR 0003: Provision once, re-provision on rejection, back off with jitter

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

DPS guidance is not to provision on every boot: registrations are throttled per service
(1,000 per minute by default), a status lookup costs the same as a registration, and a whole
fleet rebooting after a power cut would hit DPS at once.

## Decision

- The device **caches its assignment** (`state/<id>.json`, written atomically) and connects
  straight to that hub on later boots.
- It **re-provisions** only when the hub rejects its identity, after three consecutive connect
  failures (the hub may have been replaced), or when the operator calls the `Reprovision`
  direct method. The enrollment group's policy, *reprovision and migrate data*, keeps the twin.
- Transient failures are retried with **exponential backoff and jitter**, never below 5 seconds,
  and devices start with a random stagger. Only two outcomes are **final**: a disabled
  enrollment (which is how revocation reaches the device) and a certificate DPS rejects.
  Everything else, including DPS being unreachable during a long outage, is retried
  indefinitely with backoff capped at 5 minutes; a device in the field must not give up.
- With `connection_retry=False` the application owns reconnection, so it treats every way the
  SDK reports a lost or refused session as recoverable: `OperationCancelled` for a send in
  flight when the connection goes, and a generic `ClientError` for a 403 from a hub over its
  daily quota (both seen in a live run). The reconnect delay grows while sessions keep failing
  before any telemetry is delivered, because a hub over quota accepts the connection and
  rejects every operation; without that the fleet would reconnect every 5 seconds for hours.
- The SDK closes the provisioning connection only after an `assigned` result, so every other
  outcome shuts the client down explicitly to avoid leaking one connection per attempt.

## Consequences

- A normal boot costs no DPS operation, and reconnect storms are spread out.
- A stale cache costs one failed connect before recovery.
- Device state on disk is not secret (hub name, device ID).
