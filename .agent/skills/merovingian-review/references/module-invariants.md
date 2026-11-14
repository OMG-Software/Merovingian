# Module invariants

What a diff in each directory must not break. Each line is a check followed by its source, `path#heading`. The
directory's `AGENTS.md` is binding and holds more than this list. This is the shortlist of what reviewers have to
look at every time. Read the `AGENTS.md` itself before judging a change to that directory.

## Cross-cutting (check on every diff)

- **Lock scope around I/O.** No network call, SMTP send, Argon2id hash or IPC round trip runs under `runtime.mutex`,
  a store lock or the federation state mutex. Use `RuntimeLockRelease` around the call only. After re-locking,
  re-validate what the code depends on (`src/homeserver/AGENTS.md#The runtime lock and blocking calls`).
- **Caps on everything a client or remote can grow:** rows per user, array lengths, walk depths, matcher steps,
  in-flight requests. At the cap, refuse; never evict. Work under the lock is at most linear in request input
  (`src/homeserver/AGENTS.md#Work under the runtime lock is bounded by the request`).
- **Main-process-only:** signing, email, appservice registrations, database access, the policy-server hook. The
  worker relays to main, and main re-verifies (`src/federation_worker/AGENTS.md#Rules — non-negotiable`).
- **No thread before hardening** (ADR-0082): pools, parker and log writers start after Landlock and seccomp.
- **Fail closed:** signing, discovery, IS and push resolution, decoder sandbox, key validation, namespace regex,
  ClamAV, Landlock and seccomp.
- **Secrets** live in `SecretBuffer`, are compared in constant time, and are never logged.
- **Outbound** goes only through `OutboundClient` to SSRF-safe pinned addresses.
- **Indexes and maintained counters, not scans,** for anything a request touches.
- **Single-source helpers are not re-derived:** `EventId.hpp`, `RoomVersionPolicy`, `HistoryVisibility`,
  `room_read_access_for`, `parse_size_limit`, `QueryParams`, `request_header`.

## src/appservice

- Namespace regexes are compiled once in `Namespace`'s constructor and matched with `std::regex_match`, never
  `regex_search`, on length-bounded input. A malformed pattern matches nothing (ADR-0613).
  `src/appservice/AGENTS.md#Namespaces`
- Cleartext `http` only to a loopback IP literal or an operator-listed host. The check runs at parse **and** in
  `AppserviceClient` (ADR-0515). `#Security rules`
- `as_token`/`hs_token` in `SecretBuffer`, never logged, compared in constant time. `#Security rules`
- Identity assertion (`?user_id=`) stays inside the asserting service's namespaces. It never reaches account
  management or admin routes (ADR-0611). Other services' exclusive namespaces are honoured (ADR-0688). `#Security rules`
- Fan-out takes an ADR-0079 slot before the first outbound call and releases `runtime.mutex` around it. A bridge
  that is down never turns a 404 into a 502 (ADR-0181). `#Third-party lookups`, `#Ping`
- Appservice responses are untrusted. `instance_id` is minted by the homeserver. `#Third-party lookups`
- `ts` is validated and never forwarded in the rewritten query (ADR-0303). `#Timestamp massaging`
- The worker loads no registrations (ADR-0296).

## src/auth

- Tokens are hashed before storage, compared in constant time and never logged. Session lookup compares full
  hashes in the caller's predicate, with no miss fall-back scan. `src/auth/AGENTS.md#Session lookup and retention`
- Revocation is one-way. A failed revoke stays retryable, and the session is marked revoked only after durable
  writes (ADR-0407). `#Security rules`
- Argon2id runs outside `runtime.mutex` after `try_acquire()` admission, which answers 429 rather than a failed
  attempt. After re-lock, re-validate. Never keep a `LocalUser` pointer across the release.
  `#Argon2id admission and the runtime lock`
- The login throttle and the UIA password checks stay separate. `#Failed-login throttle`
- Identifiers split on the **first** `:`. The reserved localpart `remote-media` is refused on every
  account-creation path (ADR-0178). `#Security rules`
- UIA sessions are capped and answer 429, never evicting (ADR-0683). Login on an existing device deletes earlier
  rows (ADR-0590). Login tokens are never persisted (ADR-0548). `#UIAA`
- The production password cost is pinned by `tests/password_cost/` (ADR-0510).

## src/canonicaljson

- Sign or hash only `Serializer.hpp` output, with `signatures` and `unsigned` stripped via `Signable.hpp`.
  `src/canonicaljson/AGENTS.md#Critical constraints`
- The parser keeps rejecting duplicate keys, non-canonical input, integers outside ±(2^53−1) and floats.
  `#Canonical JSON rules (from spec)`

## src/config

- Validate at parse time. Other modules read only `RuntimeConfigSnapshot`. `src/config/AGENTS.md#Rules`
- Every byte limit goes through `parse_size_limit`. An unparsable value is rejected, because it would otherwise
  parse to 0, which means "no limit". `#Size limit parsing`
- `ReloadPolicy.cpp` stays in step with the user manual's reloadability section. A new key goes into **both**
  example configs, BSD included (ADR-0738). A documented key is enforced or removed (ADR-0498): grep for its reader.
- Effective config is logged without secrets or TLS key paths.

## src/core

- `SecretBuffer`, `FileDescriptor` and `Error` are the only forms for their jobs. Query parsing goes only through
  `QueryParams`. `src/core/AGENTS.md#Rules`
- A semaphore slot is returned only by `SemaphorePermit`'s destructor. Capped parallel work uses
  `run_bounded_parallel` (ADR-0267).
- A mutex in a copyable type is a `CopyableMutex` by value (ADR-0517).
- A client-chosen term in client-chosen text uses `FoldedSubstringMatcher` with `max_search_term_bytes`, never
  `std::search` (ADR-0330).

## src/crypto

- libsodium only in `src/crypto/`, `src/events/`, `src/auth/` and `src/core/SecretBuffer.cpp` (ADR-0014). The
  gate enforces this.
- Signing fails closed. Key material is never logged. Remote keys and key IDs are shape-validated before use.
  `src/crypto/AGENTS.md#Security rules — non-negotiable`
- Master key identity and bytes come from **one** open. `#Security rules` rule 6
- Do not bypass `Ed25519Provider`. The worker's provider refuses everything (ADR-0078). `#Provider interface pattern`
- `hmac_sha1` is for TURN only (ADR-0480). Add no new SHA-1 use.

## src/database

- Prepared statements with bound parameters. Never log parameters, and never retain committed statements outside
  tests. `src/database/AGENTS.md#Security rules — non-negotiable`
- Every BLOB write sets `BoundValue::binary`.
- One transaction is one pooled lease. Never take a second lease while holding one: that deadlocks (ADR-0154).
- A read that combines several tables into one picture of a room runs in one read transaction (ADR-0161).
  Federated join writes are single transactions (ADR-0714).
- Reads go by index, never scan. `PersistentStore` mutexes follow ADR-0517. A member added to `PersistentStore`
  is added to every hand-written copy, move and serialise path too.
- Schema changes go only through `migrations/` (ADR-0224). Nothing but SQLite opens an SQLite file (ADR-0157).

## src/email

- Refuse, never repair: every address passes `is_safe_mailbox_address` before libcurl or any header.
  `src/email/AGENTS.md#Rules — non-negotiable`
- TLS is required (`CURLUSESSL_ALL`) unless the server is a loopback literal and the operator set
  `require_tls=false` (ADR-0220).
- The SMTP password is read per send into `SecretBuffer`. `send_smtp_message` is never called with a lock held.
- Content is the unread count and server name only (ADR-0219), or the 8-character code (ADR-0481).
- Main process only.

## src/events

- Event IDs come only from `EventId.hpp`, with the room version from `RoomVersionPolicy`. v1 and v2 stay
  unsupported (ADR-0076).
- `event_id` stays in the signed payload (ADR-0397).
- Authorisation runs before persisting any local event or inbound PDU. Rules go into `IndexedAuthEvent`, never as
  a per-event JSON walk (ADR-0693). `src/events/AGENTS.md#Authorization rules`
- Auth-chain walks are bounded and fail closed on missing events. `#State resolution`
- Redaction uses the power levels this server recorded. `power_levels_known=false` means nobody qualifies
  (ADR-0586).
- Ingested PDUs are stored via `without_unsigned` (ADR-0402).

## src/federation

- Authenticate X-Matrix before touching the body. Verify every inbound PDU signature, our own server's included,
  before it enters the graph. Check the restricted-join authorising signature on **every** admission path:
  `/send`, send_join, worker relay, backfill (ADR-0171). `src/federation/AGENTS.md#Security rules — non-negotiable`
- Keys come only via `RemoteKeyCache`. Fetches go through admitted paths under `key_resolution_max_in_flight`
  (ADR-0155).
- Authorise before persistence. Rejected and soft-failed events are never relayed as normal.
- Room-scoped reads check `origin_may_read_room`, with the origin taken from authentication, never from the query
  or body. State at an event is the recorded state (ADR-0363).
- At most one delivery thread per destination. Never hold a `FederationDestination&` across a network call, and
  keep no process-global resolver state on delivery threads (ADR-0354, ADR-0355).
- `FederationRuntimeState::mutex` is not recursive (ADR-0518). `#The federation state mutex is not recursive`
- Events build only on same-room events (ADR-0583). Received PDUs pass `pdu_format_violation` (ADR-0399).

## src/federation_worker

- The worker never holds the signing secret and never signs (ADR-0078).
  `src/federation_worker/AGENTS.md#Rules — non-negotiable`
- The worker opens no database, on either backend. Its store is filled from main under one-use permits
  (ADR-0733, ADR-0735).
- Landlock, then seccomp, before any thread. It refuses to run unsandboxed. `#Hardening`
- `local_pool` and `relay_pool` stay separate, routed by `federation_endpoint_requires_main_relay`.
- `room_sync` runs on `reload_pool` through `RoomReloadCoalescer` and `StoreReadGuard`. Hold no lock across IPC,
  and copy what a table lends before releasing (ADR-0623).
- Never `channel->stop()` from a handler. Drain pools before stopping the channel.
- Relayed EDUs and queries are bound to the request main verified (ADR-0395, ADR-0595).
- **A new federation handler in main needs its worker path** (relay or snapshot), and the reverse. Check both
  sides and the routing table.

## src/homeserver

- No blocking network call under `runtime.mutex`. `RuntimeLockRelease` wraps only the call. Copy the signing
  secret into an owned `SecretBuffer` first. `src/homeserver/AGENTS.md#The runtime lock and blocking calls`
- Work under the lock is linear in request input. Per-user row counts are capped with the documented errcodes:
  `400 M_TOO_LARGE` (ADR-0173). `#Work under the runtime lock is bounded by the request`
- Worker frames are untrusted. Relayed PDUs are re-verified with main's resolver **before** taking
  `runtime.mutex`, and the envelope is rebuilt from the verified event (ADR-0171).
  `#Federation worker relays are untrusted input`
- Every endpoint returning room events goes through `HistoryVisibility`. Every endpoint returning state or a
  roster goes through `room_read_access_for` (ADR-0084), with a conformance scenario.
  `#Read paths that return room events or state`
- Route matching compares the path without the query string (ADR-0420).
- Never call `handle_local_http_request()` with a real client body. `#Architecture boundaries`
- Large-body routes authenticate before reading the body and opt out of the default cap explicitly.
  `#Body size limits`
- Each connection has exactly one owner, passed by move. Never touch a parked poll after `park()`
  (ADR-0569/0570).
- Operator routes dispatch before the general token gate, so each judges a locked or suspended admin itself.

## src/http

- Rate limiting runs before auth. Per-client limits key on `client_address_key`. `src/http/AGENTS.md#Rules`
- `OutboundClient` never resolves hosts: it needs `pinned_addresses`. Invalid header names and values are refused
  before any I/O (ADR-0180). URLs are logged without the query (ADR-0418).
- Headers are looked up through `request_header`. Admission via `InFlightBudget` never queues.

## src/identity

- IS hosts resolve to SSRF-safe pinned addresses. HTTPS only, allowlist checked at call sites.
  `src/identity/AGENTS.md#Security rules (non-negotiable)`
- `id_access_token` is validated before it becomes a header (ADR-0180).
- Only the IS proves 3PID ownership. `parse_validated_3pid_response` fails closed.
- The test-only discovery seam stays empty in production.

## src/ipc

- Mutually authenticated key exchange, and no libsodium here. `src/ipc/AGENTS.md#Security model — non-negotiable`
- No signing frame, and no token, Authorization header or secret in any frame. Add narrowly typed requests instead.
- Oversize frames fail visibly via `worker_ipc_frame_bytes` (ADR-0368). Frames are valid UTF-8 (ADR-0321). A
  failed `write_frame` is never ignored (ADR-0322).
- Pending requests carry main-owned origins and digests, never worker JSON (ADR-0595).
- The reader thread only routes frames. Handlers run on the dispatch thread, and a handler never stops its own
  channel. `#Thread safety - the reader/dispatch split`

## src/media

- The internal pipe format is built only in `ClientServerRuntime.cpp`. `src/media/AGENTS.md#Internal body format`
- Declared and sniffed MIME types are derived independently. Unknown types are quarantined. Content-Disposition
  goes through `media_content_disposition` (ADR-0211).
- Readers of `pending_uploads` test `expires_at_ms` (ADR-0589). Remote cache records are classified by
  `from_remote_fetch`, never by the owner string (ADR-0178).
- Quotas use maintained counters, not record scans, and are charged for deduplicated uploads too (ADR-0689).
- The decoder runs only after `apply_decoder_hardening()` and refuses without a sandbox (ADR-0419). The ClamAV
  scanner fails closed (ADR-0565).

## src/net

- `SOCK_CLOEXEC`/`O_CLOEXEC` via `FileDescriptor`. Pool tasks never throw. `src/net/AGENTS.md#Rules`
- No worker waits on a quiet socket: `ConnectionParker` does. The parker mutex is a leaf. A per-client key gets at
  most 1/16 of the parked budget (ADR-0719).
- Shutdown order: stop accepting, stop the parker, drain the pools.

## src/observability

- Never log secrets. One record is one physical line. Field values are capped. URLs are logged without the query.
  `src/observability/AGENTS.md#Rules`
- Unauthenticated per-request audit events pass through `AuditRateGate` (ADR-0080). Audit text goes through
  `bounded_utf8`.
- Writer threads start after hardening. The log file opens only through `LogFileSink`.
- Admin routes live in `admin_routes` (ADR-0504). There is no shutdown route (ADR-0505).

## src/platform

- Hardening runs before any socket opens. A self-check result of `unknown` or `disabled` blocks start-up.
  `src/platform/AGENTS.md#Security rules — non-negotiable`
- Every filter is installed with `SECCOMP_FILTER_FLAG_TSYNC`, and any non-zero result is a failure.
  `ignore_sigpipe()` is the first call in every `main()`.
- Profiles that allow `fcntl` or `ioctl` filter the commands. `TIOCSTI` and `TIOCLINUX` are never allowed
  (ADR-0731). A child spawned under main's filter needs main's list to allow its calls (ADR-0643). Filters stack
  across fork and exec.
- The BSD gate and decoder confinement travel together (ADR-0378). On the platforms the gate refuses, it must
  refuse, not report success.
- A filter change needs a real-kernel test that **fails**, not skips, when the filter is wrong.

## src/push

- `PushRules.cpp` is pure. An unrecognised condition never matches. `src/push/AGENTS.md#Rules — non-negotiable`
- Gateway URL: HTTPS, path exactly `/_matrix/push/v1/notify`, resolved through filtered discovery.
- No network call under the caller's locks. Deliveries, registrations and retries are bounded.
- Globs are linear, never `std::regex`, with one `GlobBudget` per evaluation (ADR-0175, ADR-0607).
- User rules are bounded on write and on read. Email pushers go only to the user's own 3PID (ADR-0219).

## src/rooms

- Get `RoomVersionPolicy` before any auth, state resolution, event ID or redaction work. No version logic
  elsewhere. `src/rooms/AGENTS.md#Room version policy`
- `room_creation_encryption_policy` is the only create-time decider (ADR-0445). `#Encryption policy`

## src/sync

- Every read of events or state goes through `HistoryVisibility` (one per request) and `room_read_access_for`.
  The "shared" rule compares depth, not stream ordering (ADR-0308).
  `src/sync/AGENTS.md#History visibility and room read access`
- Long-poll: take the cursor before rerunning and a new one after waking. A publish is scoped only when its
  audience is certain (ADR-0437). `#Long-poll behaviour`
- `sync_pool` is separate from the main pool. `ParkedPollRegistry`'s mutex is a leaf.
- Redactions are withheld until they apply. Filter lists and examination budgets are capped (ADR-0656/0657).
- Token families: `/sync` `next_batch` is the composite token, while `/messages` and `prev_batch` use plain stream
  orderings. Sliding-sync `pos` never regresses. `#Stream token format`

## src/trust_safety

- The engine decides; the caller acts. No hard-coded moderation decisions. `src/trust_safety/AGENTS.md#Rules`
- The policy-server hook is built by `resolve_policy_server_hook` (ADR-0361) and consulted in main only.
- `IgnoreList` is shared by homeserver, sync and push: a change must hold for every call site.

## migrations

- Never edit an applied migration. `001_initial_schema.sql` is frozen (ADR-0224). A change is a new numbered
  file, plus its step in `upgrade_migration_catalog()` and its downgrade. `migrations/AGENTS.md#Safety rules`
- Next number is the maximum plus one, contiguous. Check that parallel branches have not taken it. Format and
  header follow `#File format`.
- Every new table is classified for the federation worker. `#Federation worker classification`
- `NOT NULL` additions need a `DEFAULT`. No drops without approval. Update `docs/database-persistence.md`.

## packaging

- Versions match `meson.build`. Services drop privileges. The systemd unit keeps `PrivateTmp`, `NoNewPrivileges`
  and `ProtectSystem=strict`. `packaging/AGENTS.md#Rules`
- No hard-coded paths. BSD packages install the BSD example config (ADR-0738).
- PostgreSQL: separate migration and runtime roles. The worker has no role (ADR-0733).

## scripts

- `reject-unsafe.sh`: fix the code, never add an exception. `scripts/AGENTS.md#Rules`
- Scripts are idempotent and print what they changed.
