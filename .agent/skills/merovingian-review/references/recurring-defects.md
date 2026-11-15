# Recurring defects

The defect classes this project has shipped and then fixed, with the question that would have caught each. The
instances cite the ADR, version or PR, so a reviewer can read what happened. Ask every applicable question of
the diff, and record the classes you checked in the evidence log.

## Locks, pools and concurrency

**L1. Expensive work under `runtime.mutex`.** A sliding-sync sort comparator rescanned the store on every
comparison (ADR-0171/0172). Other instances: a quadratic multipart boundary scan (ADR-0176), an uncapped
account-data scan (ADR-0173), per-member regex compiles, push-glob allocation per character (ADR-0175), and a
quadratic expired-upload sweep (ADR-0589). Every high finding of the 1.0.0 release-candidate audit was of this
family (ADR-0693, ADR-0694, ADR-0713).
> For each loop, lookup or match the diff adds on a request path: what is its cost in attacker-controlled input
> and in total store size? Does it run under the lock? Where is the index, the cap and the linear matcher?

**L2. A lock held across network, IPC or SQL waits.** The IPC reader ran handlers inline and deadlocked against
`pdu_ingest` (0.10.29). The recursive-release stall shipped three times (ADR-0002 to ADR-0006). The auth chain is
now written with the lock released (ADR-0714).
> Does any new call to the network, the worker or a slow store path happen with the lock held? After the
> release, does the code re-validate before acting? Does it use the one release primitive?

**L3. A shared pool starved.** TLS long-polls exhausted the main pool and starved federation (0.9.1). Remote media
fetches took a dedicated pool (ADR-0121). Parked waits and per-key budgets: ADR-0570, ADR-0719, ADR-0720/0721.
> Which pool thread blocks, for how long, and who else shares that pool? Is there both a per-key cap and a
> global cap?

**L4. Wake-ups not scoped.** Element X polled every 70–150 ms because wake-ups ignored what the connection asked
for (0.10.50–0.10.53). A destructor broadcast undid per-user scoping (ADR-0437). The relevance check was unbounded
(ADR-0609).
> Does a new publish wake only its audience? Does the generation move even when positions do not?

**L5. Thread and resource lifetime.** Thread scopes published stack addresses (ADR-0529). A blob was released
twice (ADR-0636). `IpcChannel::stop()` needed `shutdown()` before `close()`. `std::jthread` is missing on BSD libc++
(ADR-0167).
> Is every thread joined and every resource released on every exit path, including exceptions and early returns?

## Worker and trust boundaries

**W1. A main-side handler without its worker path, or the reverse.** `send_join`/`leave`/`knock` accepted on the
worker were never relayed, so joins were invisible to main (0.10.19). The worker's key resolver returned nothing,
which failed dozens of Complement tests with 403 and then 429 (ADR-0263). Backfill and worker-relay paths skipped
the restricted-join signature check (ADR-0171). The OTK claim relay was not bound to a request
(GHSA-3p5v-vrg8-f545, ADR-0595).
> Which process runs each new federation, key, EDU or membership handler? Does the worker have its relay or
> snapshot path? Is the relay bound to a main-verified request? Does a test drive it through a real worker
> subprocess?

**W2. The worker given too much.** The worker could recover the signing key (0.12.12 audit; ADR-0015, ADR-0078).
It opened a database until 1.0.1 (ADR-0733 to ADR-0736). One bad frame ended the whole channel (ADR-0321,
ADR-0322).
> Does new code give the worker a credential, a database handle or a readable path? Does a bad frame fail one
> request or the channel?

**W3. Sandbox filters wrong or silently absent.** An off-by-one in the BPF made worker seccomp allow everything,
and its real-kernel test skipped (0.12.19). Other instances: `fcntl` and `ioctl` commands (ADR-0642/0643),
`TIOCSTI` (ADR-0731), and a NetBSD decoder with no confinement that reported success (ADR-0419). Capsicum forbids
opens after `cap_enter` (ADR-0739).
> Is every new syscall, open or connect in a sandboxed process allowed by every filter that stacks? Does a
> real-kernel test fail, rather than skip, when the filter is wrong? Does an unsupported platform refuse?

## Verification, authorisation and visibility

**V1. A check on one ingestion path but not its siblings.** The restricted-join signature check was missing on
relay and backfill (ADR-0171). `authorising_user_member` was never filled in on one path (0.12.32).
`prev_events` were not bound to the PDU's room (ADR-0583). Alias and encryption content checks did not run for
every local writer (ADR-0588).
> List every path that stores an event or applies state: `/send`, send_join/leave/knock, worker relay,
> backfill, invites, local writers, appservices. Did the diff change one and leave the others?

**V2. A structural check where a cryptographic or semantic one is needed.** `event_has_signature_from_server`
accepted any non-empty string. Every known unexpired key must verify (ADR-0183). Retired keys never authenticate
(ADR-0425). Redaction authority comes from room state (ADR-0586).
> Could a forged value of the right shape pass? Is the test's forged input signed with a wrong key?

**V3. Visibility leaks.** A user who had left paged past the leave in `/messages` (ADR-0311, ADR-0357). Other
instances: `/members?at=` (ADR-0414), shared history served to a server with no user in the room (ADR-0585), and
lazy-loaded state of a left room (ADR-0450).
> What does a user who left, was banned or never joined get from this path? What does the spec say for each
> `history_visibility` value?

**V4. Whose authority.** An appservice acted as server administrator (ADR-0611, ADR-0628). A join was sent by
someone other than the joining user (ADR-0612). A resident claim moved a local user's membership (ADR-0630). A
deactivated account's token still worked (ADR-0626). Operator routes dispatch before the token gate.
> Whose authority does this path run under? Is it checked on every route that reaches it, including routes
> dispatched before the general token gate?

## Input and bounds

**I1. Unbounded per-user or per-request collections.** Fallback keys (GHSA-3p9g-gpvx-2cx9, ADR-0594). Others:
account data (ADR-0173), aliases and devices (ADR-0582), invites and knocks (ADR-0619/0620, ADR-0707/0708),
createRoom initial state (ADR-0316), key backup (ADR-0606), filter lists (ADR-0657), sliding-sync `rooms` arrays
(ADR-0174, ADR-0663) and thumbnail output (ADR-0641).
> Where is the cap, what does hitting it return (`400 M_TOO_LARGE`, ADR-0173), and does a test hit it?

**I2. Matcher and parser complexity.** Push globs (ADR-0175, ADR-0343, ADR-0607), search (ADR-0330), ACL globs
(ADR-0640), filter `*` (ADR-0541), directory search (ADR-0724), unread counts (ADR-0655).
> Is the matcher iterative and linear, with a step budget? Is there any `std::regex` or recursion on attacker
> input?

**I3. Encoded versus decoded identifiers, and path versus path-plus-query.** Shard routing hashed the raw `%21`
room ID but the notifier used the decoded one, which gave a permanent `make_join` 404 (0.10.18). Thirty-four
handlers compared the target with the query string attached (ADR-0420). The `?filename=` upload route was missed
(0.9.13).
> Is each path identifier decoded exactly once, before every compare, hash and lookup? Does route matching use
> the path alone?

**I4. A status code, error or field set the spec does not say.** Audit expectations of 403 contradicted the spec
(200 before the ban; 404). Unknown endpoints answer `404 M_UNRECOGNIZED` before auth (ADR-0230).
Federation errors are spec-shaped (ADR-0280). Membership answers carry spec fields only (ADR-0538). Transaction
limits use spec values (ADR-0539).
> Does the expected status, errcode or field come from a cited spec section, not from Synapse, Complement or an
> audit report? Where the spec is silent, is the project convention ADR followed?

## Sync

**S1. Missing or wrong response fields.** Timeline and `required_state` events lacked `event_id`, and Element X
silently dropped the messages (0.10.5x). `limited` and `prev_batch` were computed from the store size (0.5.16).
Sliding-sync timelines had no `limited` or `prev_batch` (0.12.45). `full_state` was parsed and ignored (0.12.73).
> Diff the response against the spec schema field by field. Does a test assert content?

**S2. Token and ordering confusion.** To-device `stream_id` was stored as TEXT and sorted "10" before "9"
(ADR-0426). A token ahead of the streams poisoned the counter (ADR-0315). The restore epoch is now in tokens
(ADR-0592). The lazy-member ack keys on the exact `next_batch` (ADR-0450).
> Which token family does each field use? Is the ordering numeric? Can a client abort a long-poll and retry
> without losing data?

## Persistence

**P1. Not atomic, or memory and store disagree.** A federated state commit let a local write in between
(ADR-0696). Admin actions and their audit rows were separate (ADR-0629, ADR-0687). A join was committed in parts
(ADR-0714). `/keys/upload` stored and announced keys before judging the whole body (0.12.76). Hand-written
`PersistentStore` copy operations omitted later members (0.12.79).
> What is the state if write N of M fails or the process dies? Is it one transaction, with memory updated after
> commit? Did a new member reach every hand-written copy and serialise path?

**P2. Identifier reuse and number collisions.** One transaction ID was reused across destinations although it
was the primary key (0.12.34). The `remote-media` localpart could forge the quota sentinel (ADR-0178). Parallel
work duplicated migration and ADR numbers (ADR-0543).
> Is the identifier unique for its key? Do migration and ADR numbers collide with other open branches?

## Outbound and configuration

**O1. Outbound hygiene.** CRLF injection via `id_access_token` (ADR-0180). Others: the URL-preview SSRF gate
(ADR-0213), appservice cleartext rules (ADR-0515), the four-redirect limit for `.well-known` (ADR-0483), and
failures charged to the wrong party (ADR-0081, ADR-0346, ADR-0347).
> Is the answer trusted? Is it bounded in bytes, time and redirects, and counted against an in-flight budget
> (ADR-0079)? Did `tests/tooling/test_outbound_answer_trust.py` run?

**O2. Configuration nothing enforces.** `security.encryption.*` was documented but never read (ADR-0445/0446).
A migration lock key was declared and never used. A documented key is enforced or removed (ADR-0498).
> Grep for the identifier being **used**, not only defined. Does a new key have a reader, a test that flips it,
> and a doc row?

## Build, platform and tests

**B1. Green on one toolchain, red on another.** GCC-only `-Werror=null-dereference` under LTO, and `-Wshadow` on
lambda parameters. BSD `#if` blocks and fuzz targets are not in the WSL compile database. NetBSD `res_query` has
one global state (ADR-0355). An fd-sweep test closed libsodium's cached `/dev/urandom` descriptor on NetBSD.
> Is any changed code in a platform `#if` block, a file outside the compile database, or a GCC-only warning
> path? Was it compiled there?

**T1. Tests that cannot fail.** A script ran tags after the build failed, so the old binary passed. PostgreSQL
scenarios "skipped" with success. An unreadable `/proc/<pid>/fd` was counted as zero (1.0.1). An unsigned
difference was compared with zero (1.0.1). A network guard with hidden visibility passed its own scenario while
libcurl walked past it (0.12.77).
> Was each new test seen failing against the code without the fix?

**T2. Tests pinning the old behaviour, or the author's assumption.** Six older assertions expected a stranger to
read shared-era history, while tag-filtered runs stayed green (0.12.83). Audit "Test:" lines were taken as spec.
> Does the diff edit an existing assertion? Is the new expectation cited from the spec? Was the full suite run?

## Process

**R1. Delegated-work defects.** Declared-but-unwired constants. Invented APIs. Wrong expectations written
confidently. Whole-file reformatting. Workstreams green alone but broken together.
> Is every new identifier called somewhere real? Are hunks confined to the regions the change needed? Was the
> merged tree built?

**R2. Docs, ADR and CHANGELOG drift.** Branches update the user manual and CHANGELOG but not the owning guide:
threat model, auth-identity, trust-safety, media repository, capability gaps. Comments cite deleted audit reports.
ADRs cite numbers that have no file (ADR-0543).
> Which docs in the `docs/AGENTS.md` table does the change invalidate? See [obligations.md](obligations.md).

## Decisions that look like bugs but are not

Do not report these as defects. Each is recorded:

- No HTTP shutdown route (ADR-0505).
- Cap hit answers `400 M_TOO_LARGE` (ADR-0173). An oversized `/send` event type stays 413.
- `make_join` with no tips answers 404 (ADR-0318).
- Refused send_join/leave/knock events are never stored (ADR-0591).
- `max_transaction_pdus` and `max_transaction_edus` accept only the spec values (ADR-0539).
- The worker opens no database (ADR-0733).
- A worker that cannot start makes the server exit with code 80 (ADR-0377).
- NetBSD is refused at the BSD gate on purpose (ADR-0378).
- `security.encryption.*` is enforced at room creation only (ADR-0446).
- Digit separators (`900'000U`) stay. A metric tool that miscounts them gets a false-positive dismissal, not a
  code change.
- Related fixes that serve an open branch's goal share that branch and its version. Do not ask for a split.
