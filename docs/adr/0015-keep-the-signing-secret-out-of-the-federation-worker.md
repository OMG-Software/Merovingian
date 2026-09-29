# Keep the signing secret out of the federation worker

* Status: superseded by [ADR-0078](0078-the-federation-worker-never-signs.md) — Superseded by ADR-0078 for the signing-oracle part (the `sign_request` frame is gone); the signing secret still never enters the worker
* Date: 2026-09-06

## Context and Problem Statement

The federation dispatch worker is a separate process that must produce Ed25519
signatures for outbound requests. It could hold the Matrix signing key itself,
or ask something else to sign.

The worker is the process most exposed to hostile input, which is the reason it
is a separate process at all.

## Considered Options

* The worker sends `sign_request` IPC frames; main signs and returns only the
  signature
* The worker loads the signing secret from the database at startup

## Decision Outcome

Chosen option: "The worker sends `sign_request` frames". Main signs with its
in-memory production provider and returns only the unpadded base64 signature.

### Positive Consequences

* **A compromised worker can request signatures but cannot exfiltrate the
  signing key.** That is the entire point of the split, and it holds only as
  long as the key never crosses the IPC boundary.

### Negative Consequences

* Every outbound federation request costs an IPC round trip to main before it
  can be sent.
* Main becomes a signing oracle for the worker. The trust boundary is the IPC
  channel's authentication, not the key's location.

## Links

* [`docs/crypto-boundary.md`](../crypto-boundary.md)

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
