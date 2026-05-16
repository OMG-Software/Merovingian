# Alpha readiness

This document tracks what remains before The Merovingian is deployable as
an alpha — a real Matrix homeserver running for test users, federating
with the rest of the network, with bugs expected but the protocol
working end to end.

Production readiness is a strictly higher bar tracked separately in
`docs/01-production-readiness.md`. Coverage of individual endpoints lives
in `docs/protocol-coverage.md`; the canonical capability ledger lives in
`docs/progress.md`. This document layers on top of those — it is the
ranked roadmap.

## Definition

Alpha means federation works. The Matrix network is the product; a
homeserver that cannot federate is a chat app, not a Matrix homeserver.
A single-server "internal alpha" mode is described at the end of this
document for the period before federation is complete, but it is not the
goal.

## Current state

The transport, signing, and persistence primitives that federation needs
are in place. The orchestration and protocol completeness that turns
those primitives into a participating Matrix node is the remaining work.

Done (with citations):

- LibSodium-backed password hashing and access-token storage; Ed25519
  server signing keys generated and persisted across restart. See the
  Authentication and Rooms rows in `docs/progress.md`.
- Canonical JSON parser and deterministic serializer; Matrix
  reference-hash event IDs; Ed25519 signature attachment and
  verification. See `docs/canonical-json.md`.
- Full v6+ event auth rules and v2 state resolution wired into the send
  path. See the Rooms row in `docs/progress.md`.
- TLS for the client-server listener, including per-connection
  TLS-handshake test coverage. See `docs/http-transport.md`.
- SQLite persistence for users, tokens, rooms, events, devices, E2EE
  key material, media, and audit, restart-tested through integration
  flows. See the Database persistence row in `docs/progress.md`.
- `merovingian::http::OutboundClient`: libcurl-backed outbound HTTPS
  with peer + hostname verification, redirects refused, https-only,
  `CURLOPT_RESOLVE`-pinned DNS, bounded response body cap, and a stable
  `OutboundError` set. Per-platform TLS integration suite exercises
  valid round-trip, hostname mismatch, untrusted self-signed, and 3xx
  rejection. See the Federation row in `docs/progress.md` and the
  Federation queues row in `docs/protocol-coverage.md`.
- `perform_outbound_transaction`: composes `OutboundClient` with the
  X-Matrix Authorization header through `make_federation_signature`,
  retry-state mutation through `apply_outbound_result`, and the
  circuit-breaker short-circuit through `destination_should_retry`. See
  the Federation row in `docs/progress.md`.
- Inbound `PUT /_matrix/federation/v1/send/{txnId}` with request
  signature verification and PDU signature verification for known keys.
  See the Transactions row in `docs/protocol-coverage.md`.

## Blockers, ranked

The list below is ordered by the order it should be done in. Items
toward the top unblock items below them or remove the largest amount of
risk.

### 1. `GET /_matrix/key/v2/server` (inbound key publication)

**Why first.** Until remote homeservers can fetch our Ed25519 signing
key, every outbound request we send is unverifiable. No peer can accept
anything we send, regardless of how well the transport works.

**Scope.** Add the inbound route. Build the response from our persisted
signing key. Canonicalize and self-sign the response per the Matrix
spec. Return `valid_until_ts` matching our internal validity window.

**Effort.** Days. Mostly a thin wrapper around the existing signing
service plus canonical JSON.

**Status today.** `not-started`. See the Key publication row in
`docs/protocol-coverage.md`.

### 2. Server discovery — well-known + DNS SRV

**Why second.** `OutboundClient` requires `pinned_addresses` to be
populated by the caller. The federation security policy already
validates addresses against the SSRF rules; what is missing is the
network discovery that produces the candidate addresses for a given
server name.

**Scope.** Implement `.well-known/matrix/server` HTTPS fetch through the
outbound client (which already enforces the right TLS posture for it),
DNS SRV lookup on `_matrix-fed._tcp.<host>`, and address validation
through the existing `federation_discovery_policy`. Hand the validated
address set back as `ServerDiscoveryResult` so callers can populate
`OutboundCall`.

**Effort.** Days to a week. The DNS layer needs care (timeouts, IPv6
handling, NXDOMAIN handling).

**Status today.** `scaffolded`. See the Server discovery row in
`docs/protocol-coverage.md`.

### 3. Remote signing key fetch and cache

**Why third.** Inbound `/send/{txnId}` already verifies request and PDU
signatures for known keys. Once we can discover peers we need to fetch
and cache their keys so verification covers traffic from peers we have
not seen before.

**Scope.** Outbound `GET /_matrix/key/v2/server` through
`OutboundClient`, verify the self-signed key response against the
peer's claimed key, persist into the `server_signing_keys` table with
`valid_until_ts`, refresh on rotation. Wire the cache into the inbound
verifier.

**Effort.** Days. The transport, signing, and persistence pieces all
exist; this is glue.

**Status today.** `not-started`. See the Signing verification row in
`docs/protocol-coverage.md`.

### 4. Durable outbound transaction queue

**Why fourth.** `perform_outbound_transaction` is single-shot. No
restart survival exists for in-flight transactions. The retry-state on
`FederationDestination` is in-memory only.

**Scope.** Schema for `federation_transactions` (already partially
designed). Write pending transactions before dispatch. Update on
success and failure. On restart, scan pending rows and re-queue. Bound
total queue depth.

**Effort.** Days. Pattern is identical to existing write-through paths
in `src/database/`.

**Status today.** `partial` — types exist, persistence does not. See
the Federation queues row in `docs/protocol-coverage.md`.

### 5. Outbound dispatch worker

**Why fifth.** All of the above produces the inputs to a worker that
actually drives delivery. The worker is what makes federation happen
without manual triggering.

**Scope.** Background worker thread (or task) that pulls pending
transactions from the queue, calls `discover_server` to populate
`OutboundCall`, invokes `perform_outbound_transaction`, and persists
the result. Honors `destination_should_retry`. Backs off on circuit-open.
Drains cleanly on `ShutdownSignal`.

**Effort.** Roughly a week. The hardest part is making the lifecycle
clean — start, stop, drain — without losing transactions.

**Status today.** `not-started`. There is no consumer of pending
transactions.

### 6. Inbound `PUT /send/{txnId}` PDU ingestion

**Why sixth.** Verification works. Persisting received events into the
room event graph and applying state resolution to incorporate them does
not. Without this we can verify a peer's transaction but cannot
actually act on it.

**Scope.** Walk PDUs in a verified transaction. For each, look up
`prev_events` and `auth_events`, run the existing v6+ auth rules
against the current room state, append to the event graph through the
existing write-through path, run state resolution if there is a
divergence. Handle EDUs (typing, receipts) through a lighter path.

**Effort.** One to two weeks. The auth-rule and state-resolution code
is already there for local events; this hooks it into the federation
ingest path.

**Status today.** `partial`. See the Transactions row in
`docs/protocol-coverage.md`.

### 7. Make join / send join / leave / invite / backfill

**Why seventh.** These are the room participation flows. Without them,
users cannot join rooms hosted on a remote server, and remote users
cannot join rooms hosted here.

**Scope.** Each flow is its own state machine spanning outbound
discovery, outbound request, inbound response handling, and event
graph mutation. Make/send join is the most complex; backfill is
incremental walks of the event graph back through `prev_events`.

**Effort.** Two to three weeks for the set.

**Status today.** `scaffolded`. See the Joins/leaves/invites row in
`docs/protocol-coverage.md`.

### 8. Sync conformance and `/_matrix/client/versions`

**Why eighth.** Federation can work without these, but clients cannot
connect to us at all without `GET /_matrix/client/versions` (most
modern Matrix clients call it first and refuse to proceed if it is
missing) and cannot do useful conversation without correct sync
behavior across the failure modes.

**Scope.** `GET /_matrix/client/versions` returning a supported spec
list. Sync conformance fixtures across initial sync, incremental sync,
invite/leave room categories, presence, device updates, and to-device
messages.

**Effort.** Versions endpoint is hours. Sync conformance is days to a
week depending on how much of the Matrix v1.18 fixture corpus we
adopt.

**Status today (v0.1.51).** `GET /_matrix/client/versions` is wired
and answers with `v1.1`–`v1.18` plus an empty `unstable_features`
object before the auth check. Sync now emits the Matrix-spec response
shape — `rooms.join`, `rooms.invite`, `rooms.leave` plus top-level
`presence`, `account_data`, `to_device`, `device_lists`, and
`device_one_time_keys_count` keys — with invite and leave room
membership populated from `PersistentMembership`. Remaining work:
populate the new top-level surfaces with real behaviour (presence
updates, device-list change tracking, to-device queueing, account
data), add Matrix v1.18 conformance fixtures, and add filter and
long-polling support to `/sync`.

## Cross-cutting work in parallel

These are not on the critical path but should land before exposing the
server to external test users:

- **Rate-limit runtime accounting.** Done as of v0.1.51. `allow()` in
  `client_server.cpp` consults `http::endpoint_default_rate_limit`
  per request and applies the lower of that quota and the runtime's
  `max_requests_per_bucket` ceiling. Quota breaches return 429
  `M_LIMIT_EXCEEDED`. The window stays in request-count units for now
  so unit tests can exercise the limiter without sleeping; the
  remaining work is switching to wall-clock seconds via an injectable
  time source, durable persistence of bucket state across restart,
  and operator-tunable policy overrides.
- **PostgreSQL live integration.** SQLite is restart-tested; PostgreSQL
  has the code path but no live integration coverage in CI. Alpha on
  SQLite is fine; flag the gap if a tester runs Postgres.
- **Operator-grade structured logging.** Audit log persists; operator
  logs are not pinned to a stable JSON contract. Operators running the
  alpha will need this to triage.
- **E2EE end-to-end.** Device keys / one-time keys upload + claim work,
  but no device verification, no cross-signing, no megolm key sharing
  proven end-to-end. Most modern Matrix clients require this for
  conversations to be useful; alpha testers will see "unverified
  device" warnings until this lands.
- **Remote media fetch.** Disabled today; alpha users on
  multi-homeserver setups will see 404 for remote media.

## Single-server preview path

If a closed group of testers needs to exercise the server before
federation work completes, the server is deployable today against a
single homeserver with the following caveats:

- No federation. Users on the test instance can only talk to other
  users on the same instance.
- No remote media. Local upload and download work; remote fetches are
  disabled and fail closed.
- Client `GET /_matrix/client/versions` advertises `v1.1`–`v1.18` and
  empty `unstable_features` as of v0.1.51, so modern clients will
  proceed past discovery against this server.
- E2EE will show "unverified device" warnings in modern clients.

Treat the single-server preview as a way to surface bugs in the
client-server and persistence layers while the federation roadmap above
proceeds.

## Estimate

Items 1 through 7, done sequentially, are roughly four to six weeks of
focused work for one experienced engineer. Items in parallel (rate
limiting, PostgreSQL CI, operator logging) add days but do not extend
the critical path.

E2EE end-to-end is its own track and not estimated here.
