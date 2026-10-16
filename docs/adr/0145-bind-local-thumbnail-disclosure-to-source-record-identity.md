# Bind local thumbnail disclosure to source record identity

* Status: accepted
* Date: 2026-10-14

Technical Story: MED-4 follow-up, bounded local-source revalidation before cache
and decoder-admission work.

## Context and Problem Statement

Thumbnail generation already releases every published runtime-lock recursion
level around the real worker. Blob reads also run unlocked and revalidate
repository state afterwards. Holding that lock for the entire decode is not the
repair: a slow child must not block unrelated requests or administrative action.

The local thumbnail path nevertheless passed a repository record's borrowed
storage identity through the unlocked read and returned successful decoder bytes
without another record check. Quarantine or permanent removal during decoding
could finish first, while the pending request still disclosed its PNG. A shared
blob cannot identify the record that authorizes disclosure because available and
moderated aliases can reference the same bytes.

## Decision Drivers

* Keep slow blob I/O and decoding outside the runtime mutex.
* Own the local media/storage identity across both unlocked intervals.
* Bind disclosure to record state, storage identity and legacy visibility.
* Do not count suppressed output as a served thumbnail.
* Preserve existing federation media policy and successful thumbnail geometry.

## Considered Options

* Retain an owned local source identity and revalidate after decoding.
* Revalidate only before decoding or authorize through a shared blob/digest.
* Restore a global lock around the worker to prevent concurrent moderation.

## Decision Outcome

Chosen option: retain an owned local source identity, including the media ID,
storage ID and legacy-endpoint flag, before the blob read. The private generator
accepts that owned identity for local sources. After successful decoding and lock
reacquisition, `local_media_still_servable` must still authorize the same record
and storage identity before served accounting or response construction. Failure
returns the existing thumbnail-not-found boundary, 404 without decoded or original
media bytes.

Pre-decode admission is not a publication check. A blob/digest check would allow
an available alias to authorize a different quarantined record. Reinstating the
global lock would regress already-repaired responsiveness and prevent moderation
from progressing during slow decoding.

### Positive Consequences

* Local source identity survives repository mutation during unlocked work.
* Successful decoder output cannot override completed local record moderation.
* Available deduplicated aliases remain independently servable.
* Decoder controls, existing lock release and accepted MED-7 policy stay intact.

### Negative Consequences

* An admitted decode can still consume work before its output is discarded.
* Remote fetches do not yet carry an equivalent local-source binding through
  generation. This record accepts no remote revalidation claim.
* Output caching, per-user/global decode admission and strict policy-rule
  revocation remain separate MED-4 work; this is not whole-finding closure.

## Verification and Scope

The integration fixture uses real SQLite, authenticated loopback HTTP requests,
real upload/admin operations and two media IDs sharing one valid PNG blob. Both
ungated and gated healthy controls verify real-worker PNG geometry. A compiled
test-only gate acknowledges entry through private FIFOs, waits for release and
then execs the actual worker without touching stdin/stdout or synthesizing a
worker response. It is built as an integration dependency, not a new test entry.
Cleanup releases the gate before joining pending requests, listener/pools or
runtime teardown.

Within one complete BDD leaf, quarantine/release and permanent removal both run.
While decoding is pending, `/versions` and the administrative action complete;
reopened SQLite proves moderation is durable. Pending output must be refused,
while the shared-blob alias remains healthy. Quarantine release restores the
original record; permanent removal leaves the old identity unavailable.

Genuine RED completes 255 assertions, 249 passing and six expected PNG-disclosure
checks failing across both actions. The first fixture compilation failure was a
Catch INFO-expression precedence issue, not behavioral RED. Normal GREEN,
independent review and fresh combined verification remain pending. No remote
source, cache, per-user admission, strict policy-rule revocation, other-platform
execution or whole-audit/release acceptance is implied.
