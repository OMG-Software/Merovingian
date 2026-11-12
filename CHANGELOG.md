# Changelog

Changes from 1.0.0, the first production release, onwards. Changes before 1.0.0 are in
[CHANGELOG-pre-release.md](CHANGELOG-pre-release.md), which is no longer added to
([ADR-0740](docs/adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).

## 1.0.1

Fixes for the findings of the security audit of the 1.0.0 release candidate (run 3, at commit d9b93005): 49
confirmed findings (9 high, 30 medium, 9 low, 1 informational), plus in-repository hardening for two of the four
findings that needed validation.

### The changelog starts at 1.0.0 (ADR-0740)

* `CHANGELOG.md` now holds 1.0.0 and later. The entries of the 0.x series, up to 0.12.93, moved unchanged to
  `CHANGELOG-pre-release.md` (with `git mv`, so `git log --follow` keeps their history), which is a frozen record:
  nothing is added to it. `AGENTS.md`, `docs/AGENTS.md`, `docs/versioning.md` and the `docs/todos/` references to 0.x
  sections name the file that now holds them. The documentation site's changelog page is still `CHANGELOG.md`.

### The BSD packages ship a BSD example config (ADR-0738)

The FreeBSD, OpenBSD and NetBSD packages installed the Linux example as their `merovingian.conf.sample`. Its secret
files pointed at `/etc/merovingian`, and its SQLite path at `/var/lib/merovingian`, which no BSD package creates.
`config/merovingian.conf.bsd.example` is the BSD edition. It holds the same keys, with secret files in an
`@SYSCONFDIR@/merovingian` directory and the SQLite path in `/var/db/merovingian`, the service user's home. Its
commented clamd socket names no path, because FreeBSD and OpenBSD refuse clamd. A comment header explains how to
choose the federation worker settings on FreeBSD and OpenBSD.

- `build-freebsd-pkg.sh`, `build-openbsd-pkg.sh` and `build-netbsd-pkg.sh` stage the BSD example as the sample, with
  the placeholder filled in from the `--sysconfdir` each passes to Meson (`/usr/local/etc`, `/etc`, `/usr/pkg/etc`).
  That is the directory each rc.d script reads the config from. Each build fails if a placeholder is left. The pkgsrc
  `Makefile` fills it with `PKG_SYSCONFDIR` and installs the sample through `CONF_FILES`. The OpenBSD ports `PLIST`
  lists the sample and its `@sample` config. Linux packages are unchanged.
- `scripts/validate-phase1-config.sh` dry-runs the BSD example, filled in as the FreeBSD package fills it.
- The user manual drops the FreeBSD `sed` step and lists each BSD's config directory.
- Tests: `tests/tooling/test_example_config.py` requires the BSD example to equal the Linux example below its header,
  apart from those paths, so a key added to one example and not the other fails. It also checks that each BSD build
  script stages the BSD example for its own `--sysconfdir` and rc.d path, that the pkgsrc and OpenBSD port metadata
  install it, and that the FreeBSD fill leaves no placeholder.

### Tests brought in line with the combined fixes

* Tests written before other fixes on this branch landed now expect what those fixes do: the SQLite snapshot order
  includes `forward_extremities` (C44), `RoomService.cpp` has one direct `store_event` call (C03 writes a join's auth
  chain as an outlier batch), and the expected-skips list drops the Landlock scenario that C44 removed. The Complement
  configuration lifts the two report routes' per-user limits (C26), as it does for the other routes Complement calls in
  bursts.
* The keep-alive cap scenario connects three times from 127.0.0.1 named as a trusted proxy, whose connections have no
  client key and so count only against the server-wide cap, not a key's share of it (C01, ADR-0719). It first connected
  from three loopback addresses; the BSDs configure only 127.0.0.1, so it skipped there with the server thread still
  joinable, and destroying that thread aborted the integration binary on FreeBSD, NetBSD and OpenBSD. It now stops the
  server through `ServerStop` on every exit, as the per-address scenarios already did.
* The IPC write-failure scenario (C44, ADR-0734) closes the client's end instead of shutting down its read side:
  NetBSD and OpenBSD keep accepting writes to a stream socket whose peer has only stopped reading.
* The C44 SQLite worker scenario found the worker and read its state through `/proc`, which the BSDs lack; it uses
  `ps(1)` there. It counted the descriptors that named the database as none whenever `/proc/<pid>/fd` could not be
  read, and the worker, which clears its dumpable flag, leaves that directory readable by root alone, so the check
  passed without looking for every non-root run. It now skips that branch visibly (listed for the BSDs and the
  non-root Linux jobs) and runs it in the root container jobs.
* The `[worker_session]` thumbnail scenario skips under AddressSanitizer: the exec'd ASan-built worker starts the ASan
  runtime under main's inherited seccomp filter, which does not admit the calls that runtime makes.

### A worker cannot type into the terminal that started the server (ADR-0731)

* A server started from a shell (the bootstrap-admin step, a debug run) gave the federation worker that shell's
  terminal as stdin and controlling terminal, and the worker's seccomp profile allowed `TIOCSTI`. On a kernel that
  still honours legacy `TIOCSTI`, a taken-over worker could queue a command the shell ran after the server stopped
  (run-3 needs-validation finding NV-1, `sandbox.worker-seccomp.ioctl-denylist-admits-tiocsti-on-inherited-terminal`).
* The worker profile now kills `TIOCSTI` and `TIOCLINUX`; the decoder's allowlist already refused both.
* The supervisor spawns the worker with `POSIX_SPAWN_SETSID` and `/dev/null` on stdin. `merovingian-fed-worker` calls
  `setsid()` itself where the C library lacks the flag and refuses to start if it cannot. The thumbnail decoder's child
  calls `setsid()` before `exec`. stdout and stderr still carry the logs. Main's seccomp profile admits `setsid`, since
  a child runs those calls under main's filter; without it every worker start and thumbnail decode was killed. The
  systemd unit's `SystemCallFilter`, which covers the same children, admits it too.
* Tests: `[terminal_injection]` runs both filters against a pseudo-terminal that is the child's controlling terminal;
  `[worker_session]` checks that a spawned worker leads its own session with no terminal and `/dev/null` for stdin,
  that main's profile admits `setsid`, and that a process confined by main's profile still gets a thumbnail.

### The published provenance check pins the release workflow and the ref (ADR-0732)

* The release notes and `docs/release-process.md` gave `gh attestation verify <file> --repo OMG-Software/Merovingian`,
  which accepts an attestation made by any workflow on any ref of the repository, including `packages.yml` runs on
  branches and pull requests (run-3 needs-validation finding NV-2,
  `supply-chain.release-verification.attestation-recipe-accepts-any-workflow-and-ref`).
* Every published recipe now names `--signer-workflow` and `--source-ref`: the tarball `release.yml` on
  `refs/tags/v<version>`, a package `packages.yml` on the same tag, and a file of the rolling `latest` release
  `packages.yml` on `refs/heads/main`. The release notes fill the version in. The GPG signature is named as the
  primary check.
* `AttestationRecipeTests` in `tests/tooling/test_release_workflow.py` fails on any recipe in a Markdown or workflow
  file that lacks either flag or names the wrong workflow.
### One client address cannot fill the pending-connection budget (ADR-0719)

* A client address (an IPv6 /64) may now hold at most a sixteenth of `listeners.max_queued_connections` and of
  `server.http.keep_alive_max_connections`, so five addresses can no longer make every listener refuse new
  connections. A trusted proxy is exempt.
* A connection that is readable but waits more than 30 s for its address's share of the workers is closed instead of
  holding its slot for ever.

### A destination that answers slowly cannot keep the outbound queue and every delivery thread (ADR-0720)

* A remote server that answers every transaction with 200 after about nine seconds is no longer treated as healthy for
  the queue. A destination whose last answer took more than a quarter of `slow_attempt_ms` is marked slow: all such
  destinations together may hold at most half of the outbound queue (new rows beyond that are refused, queued rows are
  kept), and their transactions are sent only when no other destination has one ready. Order per destination is
  unchanged.

### A push gateway that answers slowly no longer holds the delivery reserve (ADR-0721)

* A push gateway is now treated as reachable only if it answers within an eighth of the delivery timeout (3.75 s by
  default). An answer between that and half the timeout clears the host's failures but removes its proof, so it
  cannot use the quarter of `server.push.max_in_flight_deliveries` kept for prompt gateways. While that reserve is in
  use, one gateway host may carry only a quarter of its usual share.

### One event's push badges share one rule-evaluation budget (ADR-0722)

* The unread badge computed for a notification ran a full push-rule evaluation, each with a fresh glob budget, for every
  event row it visited, so one wildcard rule and a room of large events could hold the server lock for seconds per
  event. All the badges of one event now share a single glob step budget; when it is spent the badge is a lower bound
  and the walk stops. The unread count in the email digest (one walk per due email) takes the same budget.

### Push rule key paths are charged to the evaluation budget (ADR-0723)

* Resolving a push-rule condition's key (for example `content.foo`) scans the event's members, which a sender can make
  thousands wide. The scan past 64 members per object now draws from the evaluation's step budget, so a recipient with
  many rules cannot make one event cost tens of millions of compares under the server lock. Ordinary events are
  unaffected.

### A directory search parses a bounded number of bytes (ADR-0724)

* `POST /publicRooms` with a search term or room-type filter (and the federation `publicRooms`) read and parsed the name,
  topic, alias and create events of every published room under the server lock. One request now parses at most 4 MiB of
  state events; past that the remaining rooms are not examined, so a search over a directory of very large rooms can
  miss matches. `total_room_count_estimate` still counts every published room.

### Abandoned join candidates stop making calls, use few threads and hold the client's slot (ADR-0725)

* Joining a room through the servers named by the client used to start one thread per candidate and release the client's
  outbound slot as soon as the request stopped waiting, while candidates still queued went on to make their full calls, up
  to 180 seconds each, outliving the request. A join now uses at most `join_parallelism` worker threads that take
  candidates one at a time, makes no call once a winner exists or the request has stopped waiting, and keeps the client's
  outbound slot until its last in-flight call ends. With `join_race_deadline_seconds` set, the calls also end at that
  deadline.
### POST /delete_devices is capped and looks devices up by index (ADR-0669)

Audit finding C02. `POST /delete_devices` accepted a `devices` list of any length (about 260,000 IDs fit in the body) and
scanned every device and session row on the server for each ID while holding the global lock. A list of more than 200
entries (the per-account device limit, repeats counted) is now `400 M_INVALID_PARAM` before the password is checked, and
repeated IDs are handled once. Deleting a device (here, `DELETE /devices/{deviceId}`, and the refresh-token device check)
now reads only the account's own device rows and the device's own sessions.

### A client key claim is capped and merges a remote answer in linear time (ADR-0670)

Audit finding C13. `POST /keys/claim` named any number of users and devices and merged a remote server's answer with a
search of the response for each accepted user, which is quadratic and ran with the global lock held. A claim naming more than
25,000 users plus devices (the cap federation already applies) is now `413 M_TOO_LARGE` before any one-time key is claimed,
and the merge looks users up in a hash set.

### A client key query reads the requested user's device keys through the index (ADR-0671)

Audit finding C19. `POST /keys/query` looped over every device-key row on the server once for each requested local user
that asked for all devices, and had no limit on how many users a request names. A query naming more than 25,000 users plus
devices (the federation cap) is now `413 M_TOO_LARGE`, and each user's device keys are read through the per-user index.

### Key signature uploads are one transaction and use indexes (ADR-0672)

Audit finding C14. Storing each uploaded key signature searched every signature row on the server and committed on its own,
and the cap check and the merge into a published key each read other signers' and other keys' rows, all with the global lock
held. An upload is now one database transaction, the signer's rows and a key's signatures come from indexes, and a replacement
updates its row in place.

### A key backup's etag no longer rehashes the backup, and a session has a size limit (ADR-0673)

Audit finding C22. Every read of a backup version and every upload of backup sessions recomputed the backup's `etag` by
hashing every stored session, with the global lock held, and a session could be up to the 1 MiB body. The etag now comes from
a digest of the sessions that each write keeps up to date, so a request reads no session; it still changes whenever the
backup's content changes and is the same after a restart. A backup session over 16 KiB is refused with `400 M_TOO_LARGE`
before anything is stored.

### A to-device queue is shared out per sender (ADR-0674)

Audit finding C12. When a device's (or a user's) to-device queue was full, a new message evicted the oldest queued rows whoever
had sent them, so any local user or federated server could delete the room keys other senders had queued for a device that had
not synced yet. Each sender (a local user, or a remote server for everything its users send) may now hold at most half of a
queue once another sender is queued there; a message from a sender at its share evicts that sender's own oldest row, and a
message that finds the queue full evicts the oldest row of the sender holding the most. No sender can fill a queue first to make
others' messages fail, no message from a sender under its share is dropped, and a sender alone in a queue is limited as before.
At the per-user bound the sender's oldest row across the user's devices goes first, as before.
### A backfilled event is recognised as stored by index, and an /event_auth answer is capped (ADR-0705)

C30. Checking whether a fetched event was already stored walked every row of the event table under the runtime lock, once
per entry of a remote server's `/event_auth` answer. It is now one lookup by event ID. The answer is also refused when it
holds more entries than `security.federation.backfill.max_auth_chain_ids`, or an entry that is not a well-formed PDU.

### A remote join no longer re-sends every local device list (ADR-0706)

C32. Each accepted remote join checked every roster member against every account and queued every device list of every
local member for the joiner's server, under the runtime lock, even for a profile change or a second user of a server
already in the room. The lists are now sent only when the joiner's server had no joined member in the room, and the local
members are read from a per-server group in the room roster.

### Remote invites are capped in bytes per sending server and in all (ADR-0707)

C04. One remote server could keep up to 16 GiB of invite records here, spread over many local users, because only the
per-user bytes and a count per server were bounded. A sending server may now hold 64 MiB of invites in all, remote invites
together 256 MiB, and one invite's `invite_room_state` is limited to 64 KiB (a 400 `M_INVALID_PARAM` over it).

### A user's knocks are capped in bytes and keep one entry per state (ADR-0708)

C31. A user could store about 128 MiB of knock state their own server chose, and every `/sync` of theirs copied and parsed
all of it under the runtime lock. A user's knock records are now limited to 2 MiB in all, a resident's `knock_room_state`
keeps the last entry for each state, and `/sync` reads the record without copying it.

### A resident's membership template can no longer add content that this server signs (ADR-0709)

C18. When a local user left, rejected an invite, knocked or joined through a remote server, that server's template content
(a `reason` or any other key) was signed by this server as the user's. The content is now rebuilt from an allow-list:
the membership, and for a join the authorising user of another server. A join template naming a user of this server as
authoriser is refused.

### A remote server can no longer smuggle `unsigned` past the strip with an escaped key (ADR-0710)

C43. A bare `GET /event` answer was kept verbatim, and `unsigned` written with a unicode escape escaped the literal search
that decides whether to strip it, so the remote server's `unsigned` was stored and served on. The strip now parses any
text with an escape, and a bare answer is re-serialised as canonical JSON.
The regression test now writes the key with a real escape (the first version spelt it literally and could not fail).

### Federation reads of main's store now hold the runtime lock (ADR-0711)

C11. The federation read providers (server ACL, room version, state, state_ids, event_auth, backfill, get_missing_events,
event) read main's store without `runtime.mutex` while writers changed it, so a remote server could race a read against a
reallocation. Each now reads under the lock in main; a federation worker is unchanged.

### A federation hierarchy request is answered by main (ADR-0712)

C47. `GET /hierarchy` went to shard 0 whatever room it named, and shard 0's copy of a room another shard owns is its
start-up snapshot, so the server ACL, the view check and the summaries could be stale. Main now answers it.

### Choosing a signing key no longer copies every cached remote key (ADR-0713)

C27. Every local send and every key-server request with a query string copied the whole signing-key table, which remote
servers could grow without limit, while holding the runtime lock. The table is indexed by server name and read one server
at a time, a remote key document may add at most 16 current and 64 retired keys, and the key-server cache matches the path
without its query.
### Composing an event reads its own room's state by key

Every event the server composes (one per `createRoom` preset step, `initial_state` entry and invitee, under the
runtime lock) was authorised against an auth map built by walking the current state of every room on the server, and
`createRoom` walked it again per remote invitee. The auth map, the authorising-user and third-party-invite auth events,
a user's current membership, the invite's stripped state, the room summary for knocks and the power and push lookups
now read the room's own state through the state index (ADR-0344). `state_rows_examined` counts what the state readers
look at; a test proves `createRoom` examines the same rows however much state other rooms hold (run-3 C35).

### State resolution reads each auth event once

The iterative auth checks built an auth map for every event of the conflicted set by deep-copying the current create,
power-levels, join-rules and member events, and the auth rules then searched those copies: the sender's level was a
walk of `content.users`, and rule 9 compared two power-levels events entry by entry. A remote room creator chooses both
the number of conflicted events and the size of the power-levels event, so one resolution under the runtime lock cost
their product. Each distinct auth event is now copied and read into an index once per resolution, the auth rules look
fields up in it, and rules 9.6 and 9.8 count the current entries at or above the sender's level instead of walking
them. Decisions are unchanged; a 9.6 refusal no longer names the entry (ADR-0693).

### The state before an event is resolved and stored once

Every PDU with more than one prev_event resolved its prev_events' state afresh under the runtime lock, whatever its
outcome, and stored the result as a group chained off the first prev_event's group; when the resolution dropped a key
that group held, the group was a full snapshot of the room's state. A remote member naming the same two old events in a
stream of small PDUs, even rejected ones, cost a resolution and up to the whole room state in stored rows each. The
state before an event is now read once per distinct prev group, a set of prev groups that has been resolved is answered
from the group holding its result, and that result is stored once, chained off a resolved group that holds every key
it keeps; the event's after-state is chained off it, so a rejected or non-state event adds no rows (ADR-0694).

### Senders without power share one cap on a room's tips

A room's forward extremities were limited only per sender server, keyed on the text after the sender's first `:`, so
one operator running a few dozen server names in a room could still make it hold enough tips that every later PDU paid
a resolution over all of them. The tips of senders who can neither ban nor change the power levels now also share
`security.federation.state_resolution.max_unprivileged_state_tips` (default 128) for the room, whatever their servers,
before a further such event that cites no current tip stops becoming one. A sender who may ban or change the power
levels is exempt from that cap and limited only by its own server's tips, so tips other servers add never keep a
moderator's ban or demotion out (ADR-0695).

### A federated state event's commit no longer lets a local write slip in between

`ingest_pdu_event` released the runtime lock for the database commit of every PDU, keeping only the room's lock. A
local client's state send takes the runtime lock but not the room's, so it could write the same current-state row inside
that window: the database kept the local event and memory the federated one, and a restart served a different power
levels, join rules or membership row than the running server had. A PDU commit that writes a current-state or
membership row now keeps the runtime lock, as a local send's commit already does, so memory always ends equal to what
the database holds; a message still commits without it (ADR-0696).

### A room's state revision moves after its state row is written

The room state revision that keeps cached send_join plans valid moved when a state event's write was prepared, not when
the row was written to memory. A send_join answered in between read the old row under the new revision and cached a plan
that later send_joins kept serving with the superseded state event, such as old power levels or join rules. Applying a
prepared state row now moves the revision after the row is written, as well as at prepare (ADR-0697).

### The federation worker opens no database; main sends it what it reads (ADR-0733, ADR-0734, ADR-0735, ADR-0736)

* On SQLite a compromised federation worker could hold a read lock on main's database file and make every write in main
  fail after its 5 s busy timeout, while its IPC channel stayed healthy (run-3 finding C44,
  `resource-exhaustion.sqlite-worker.read-lock-held-by-compromised-worker-fails-every-main-write`). On PostgreSQL its
  SELECT-only login could still exhaust connections, hold advisory locks or pin the vacuum horizon. The worker now gets
  every row it reads from main over its IPC channel, on both backends (ADR-0733).
* A frame that cannot be written whole now ends the IPC channel: it is marked unhealthy and shut down, so the supervisor
  replaces the worker. Before, `send_response` ignored the failure and the channel kept reporting healthy with its
  stream broken (ADR-0734). Test: `[c44][write-failure]`.
* A room snapshot (`load_room_snapshot`, `reload_room`) now carries the room's forward extremities and a reload replaces
  them, charged to the server of each tip's sender. `fill_store_from_room_snapshots` builds a whole store from snapshots
  in one pass with every index a hydrated store has, `load_room_ids` lists every room ID from one statement, and
  `public_signing_keys_of_server` copies a server's public key columns from memory, never a row with a secret: the
  database halves of what main will serve the worker. Tests: `[c44][snapshot-tips]`, `[c44][snapshot-fill]`,
  `[c44][room-ids]`, `[c44][server-keys]`.
* The IPC frames that carry the worker's store: the room list, a room snapshot and a server's public keys. Rows travel
  exactly (bytes that are not UTF-8 and integers past 2^53 included), are packed into pages that fit the frame cap, and
  a row too big for any page refuses the room instead of being cut. The worker's `RoomSnapshotAssembler` refuses pages
  out of order, of another room or generation, or holding another room's rows. Tests: `[c44][worker-store-frames]`.
* Main answers the worker's store requests (`WorkerSnapshotService`, on a pool of its own, one thread per shard). A room
  is read only under a permit main issued on that channel, each consumed once: the room list (read once per channel)
  permits one read of each listed room, and each `room_sync` main sends permits one read at a generation it sent
  (recorded before the notification goes out). Later pages come from memory, each once, in order, for at most 60 s. No
  lock is held across a read, never `runtime.mutex`, and the read transaction has ended before page 0 is sent. A key
  lookup is answered from main's memory, public columns, at most 256 rows, through the per-server signing-key index
  (C27, ADR-0713), so it reads the asked server's rows and not every cached key under the mutex main's signing path
  takes (`server_signing_key_rows_examined`, test `[c44][c27][server-keys]`) (ADR-0735). Tests:
  `[c44][worker-snapshot-service]` (permits, a race for one permit, no lock across the read, paging and expiry) and
  `[integration][c44][worker-snapshot-lock]` (a real SQLite file: a write without waiting is refused during the read
  and succeeds when page 0 is ready).
* The worker opens no database. Its configuration copy is switched to the memory backend with every database location
  cleared before its Landlock rules are built (so the database directory is no longer granted) and again before its
  runtime starts. It starts its IPC channel first, with the request handler held behind a gate until the runtime
  exists, and fills its store from main before hydration: the room list, then each room's snapshot, one at a time. A
  room list main refuses stops the worker; a room main cannot send is left out until its next `room_sync`. A
  `room_sync` reload asks main for the room at that generation and swaps it in under the store guard with no lock held
  across the request (`StoreReadGuard::reload_room_from`). A key-cache miss asks main for the server's public keys
  (`PersistentStore::remote_signing_key_source`), in the PDU and X-Matrix key lookup as well as the resolver, so a key
  main already verified is used without discovering its server first. On SQLite the worker no longer holds users, token hashes, the sealed
  signing secret, account data, keys, to-device rows or policy rules. Tests: `[integration][c44][worker-no-database]` (a real worker on a SQLite
  server holds no descriptor of the database or its journals, and while it is stopped with SIGSTOP a write that does
  not wait succeeds in main; it reloads once continued), `[c44][worker-database-config]`, `[c44][key-source]` and
  `[c44][reload-from]`; the existing real-worker `[integration][worker]` scenarios (`[fed10-worker-http]`,
  `[txn-dedupe]`, `[f21]`) cover the key lookup.
* **Upgrade note:** `federation.worker.database_uri_file` and `federation.worker.allow_shared_database_credentials`
  are retired and refused at start-up, each with an error naming the key, so a 1.0.0 PostgreSQL deployment with
  federation enabled must remove the `database_uri_file` line before 1.0.1 starts; the worker's role can then be
  dropped (ADR-0736). Main no longer reads a worker URI file or validates it, hands no credential to the worker, and
  passes no `--db-uri-fd` (the worker refuses it as unknown); `database.worker_conninfo_override`, the worker's
  `DbUriFd` reader, `kWorkerDbUriFd` and `packaging/postgresql/provision-federation-worker-role.sql` are removed.
  `build_worker_landlock_rules` derives no rule from the database keys, so no database directory is granted even to a
  configuration that still names one. Tests: `[c44][retired-worker-database-keys]`, `[args][c44]` (the retired
  argument), `[c44][landlock-no-database]` and `[iso4_landlock][c44]` (a landlocked child on a real kernel cannot open
  main's SQLite file for reading or writing). `test_worker_db_uri.cpp` is now `test_worker_table_load_profile.cpp`
  (tag `[worker_table_profile]`): its configuration, argument, URI-pipe and grant-script scenarios went with what they
  tested; the PostgreSQL worker-role scenario is removed.
* A worker whose store main does not fill (main is stopping, or refused the room list) now stops with "the store could
  not be filled from main" instead of "database schema validation failed", which named a database the worker never
  opens. Test: `[c44][fill-store]`.
* On FreeBSD a server with federation never ran it: main read each worker's store through a connection it opened per
  read, by path or socket, which Capsicum capability mode forbids, so the worker's first request failed and it could not
  be restarted. Main now reads through `SnapshotReaderPool`, one reader per shard opened before `cap_enter`, each leased
  for one read with its transaction ended (ADR-0739). Tests: `[c44][snapshot-readers]`; the reload-failure scenarios of
  `test_federation_worker_flow.cpp` now fail a read by renaming a table, since moving the file aside no longer does.
### A sliding sync connection keeps a bounded number of bytes of its lists (ADR-0663)

A sliding sync connection keeps a copy of its request's lists and its `conn_id` for an hour, and nothing bounded their size, so one account could hold tens of GiB of the main process. A list may now name at most 16 `room_types` and 16 `not_room_types` and 16 ranges, a `conn_id` and a list name are at most 255 bytes, a request may keep at most 64 KiB of lists, and one device's connections together at most 256 KiB; over any of these the request is 400 `M_INVALID_PARAM` and no connection state is created. The idle-connection sweep no longer walks every user's connections: they are kept in an index ordered by last use, so a request pays for the connections it removes.

### A sliding sync room timeline stops after a fixed number of rows it does not take (ADR-0664)

A sliding sync room's timeline was built by a loop that did not count rows it passed over, so a room whose newest history the caller could not see, or an ignored user had filled, was walked to its first event under the runtime lock on every initial build. It now uses the walk classic `/sync` uses, which stops after 1000 rows not taken; past that the timeline is `limited` and `prev_batch` points where the walk stopped.

### Sliding sync list filters and the notification sort no longer scan whole tables per room (ADR-0665, ADR-0666)

For each list, each joined room was tested against the filters by scanning the whole membership, current-state or receipt table, so a list cost the user's rooms times the tables, under the runtime lock. A request now learns the user's joined rooms and invites from their own membership rows, reads the room's encryption and type by the state index, parses `m.direct` once and reads each room's read markers from the user's own receipt rows through the receipt index (ADR-0737), once per room; every list and every room built shares that. The lists a room belongs to are looked up in a hash set rather than scanned in the window. The `by_recency` (with bump event types) and `by_name` sort keys are likewise read per room through the room indexes with a budget of 1000 rows per room, instead of one pass over every event and state row per list (ADR-0666).

### Receipts are indexed by room and user, and a threaded receipt must belong to its thread (ADR-0737)

Run-3 finding C23. Read receipts are now found through two indexes (by room, and by room and user), so `/sync`, the push
badge count and sliding sync read only the rows of the rooms they serve, not every receipt on the server. A threaded
receipt (`thread_id` other than `main`) is accepted only when its event is the thread root or belongs to that thread,
otherwise the request fails with 400 `M_INVALID_PARAM`, as the spec allows. One user holds at most 256 threaded
receipt rows in one room; a new one replaces that user's own oldest.

### A receipt EDU commits in one transaction (ADR-0652)

Run-3 finding C36. An inbound `m.receipt` EDU used to scan the whole receipt table several times for each receipt and commit
one database transaction per receipt while holding the runtime lock. Its accepted receipts are now stored together in one
transaction, found through the receipt indexes, and when the table is full the oldest receipts of remote users are evicted
from an ordered index, so the cost is bounded by the EDU. A local user's receipts are still never evicted.

### The ACL checks of one request share a step budget (ADR-0653)

Run-3 finding C38. The step budget of a server ACL check was per check, so one `m.receipt` EDU naming hundreds of rooms
could run hundreds of full-budget checks under the runtime lock. All the checks of one EDU (or one relayed frame) now
spend from a single budget of 1,000,000 glob steps, a single check is limited to 100,000, and the answer for an ACL and a
server name is remembered, so asking again costs nothing.

### Classic sync reads each room's own rows, and a room past the room cap still gets its news (ADR-0654, ADR-0658, ADR-0659)

Run-3 finding C34. `/sync` no longer scans the server-wide state, membership, receipt, device-list, stored-filter and
presence tables for each joined room or each request: it reads the rows of the user and of the user's rooms through
standing indexes, so a sync costs the user's own rooms and their rows. The joined rooms a sync does per-room work for are
found from the user's membership rows, an incremental sync leaves out a room that cannot have news without charging it to
`server.client_api.max_sync_rooms`, and when more rooms than the cap remain the most recently active are served. A room
with news that is past the cap is not served by that sync, as before.

### Unread counts parse a bounded number of bytes (ADR-0655)

Run-3 finding C05. Counting a room's unread notifications parsed up to a thousand events in full, plus their parents, on
every sync, however large the events were. A count now parses at most 512 KiB of event JSON; past that it is a lower
bound, as it already was at 1,000 rows. Counts of ordinary events are exact. An incremental sync also no longer counts a
joined room it is not going to send.

### /context and /initialSync stop at an examination budget (ADR-0656)

Run-3 finding C39. Both endpoints walked the room's events until they had a page of events the reader may see, so a reader
for whom everything near the page is hidden made the server walk the whole history under the runtime lock. They now
examine at most `server.client_api.max_messages_events_examined` rows (the budget `/messages` already had; `/context`
once for each side of the event), without copying the room first, and when the budget ends the `start`/`end` tokens stand
at the last row examined so the client can carry on.

### A sync filter's lists are capped at 100 entries (ADR-0657)

Run-3 finding C09. Each list of a filter (`types`, `not_types`, `senders`, `not_senders`, `rooms`, `not_rooms`,
`event_fields`) may hold at most 100 entries. A longer one is refused with 400 `M_INVALID_PARAM` when the filter is
uploaded, when it is given inline to `GET /sync`, `/messages` or `/context`, and when a filter stored before the cap is used
by a sync. Before, one filter with 100,000 patterns made every sync that used it match each pattern against every row
under the runtime lock.
### A federated join commits its answer in few transactions and writes the auth chain with the lock released (ADR-0714)

C03. A federated join committed every auth-chain event and every member row of the resident's answer separately, under the
runtime lock, so the number of commits was chosen by the resident. The auth chain is now written in one transaction with
`runtime.mutex` released, and the member rows in one transaction. The state-array and member commits still hold the lock,
because they write `current_state` and membership rows; the ADR records what releasing them needs.

### A federated join commits its auth chain and members once each (ADR-0714)

C03. A federated join committed every auth-chain event and every member row of the resident's answer separately, under the
runtime lock, so the number of commits was chosen by the resident. The auth chain is now stored in one transaction and the
member rows in one. Preparing the statements with the lock released is not done (recorded in the ADR).
### OpenID tokens are looked up by hash and capped per user (ADR-0681, ADR-0682)

`GET /openid/userinfo` no longer compares the presented token with every stored OpenID token under the global lock: the
tokens are indexed by hash and by user, so the request costs one lookup. A user now holds at most 32 live OpenID tokens
(minting another evicts their oldest), and a mint deletes every expired row with one statement in the same transaction as
the insert instead of one committed statement and one vector erase per row, which held the lock for about 94 seconds after
an hour of minting at the default rate.

### One user cannot void another user's challenge (ADR-0683)

User-interactive authentication sessions are shared by all users, and a full pool used to drop the oldest session whoever held it, so one account sending challenge-provoking requests could keep a victim from finishing a device deletion, a login token request or a registration. A session now belongs to its owner (the user, or for registration the client address) and is valid only for that owner. An owner holds at most 16, replacing its own oldest, and a full pool answers a new challenge with 429 `M_LIMIT_EXCEEDED` instead of evicting another owner's session. A request that carries a valid session no longer mints a spare one first.

### The validation session cap is per client, not per proxy (ADR-0684)

The cap on open identity validation sessions (password reset, email and phone registration, 3PID requests) counted sessions by the TCP peer address. Behind a reverse proxy every client has the proxy's address, so the per-client cap of 16 was one cap for the whole server and one client could use it up for everyone. It is now counted per client address as the rate limiter resolves it: trusted proxies and `X-Forwarded-For` honoured, IPv6 clients grouped by prefix.

### The owner of an address can always use a reset code (ADR-0685)

The password reset mail is sent at most once a minute per address across all sessions, so a caller who knew the owner's address could take each minute's only send slot with a session of their own and leave the owner a session with no usable code. A session the throttle gave no code is now judged against the latest code mailed to its address (a code typed into a session still validates only that session, and a code a session has proved is spent from all of them). Keeping the throttle per address and not per client address keeps the mail one address can be sent bounded; at most 10 reset mails a day now go to one address, whoever asks.

### Reporting no longer reads the audit log and is limited per user (ADR-0686)

Every user or event report loaded the newest 1000 rows of its type from `audit_log` under the global lock to find a repeat (a sort of the whole table on PostgreSQL), the 20 reports a minute that the reporting routes declare was never applied, and a user could report any number of distinct remote user IDs. Reports are now judged from an in-memory index filled once at start-up from the stored rows, each user is limited to 20 reports a minute and 100 distinct reports a day (a further one is 429 `M_LIMIT_EXCEEDED`; a repeat is still acknowledged without a second row), so one user can no longer fill the administrators' listing.

### A policy rule change and its audit row commit together (ADR-0687)

An administrator's policy rule change (adding or removing a rule, or the review action on either admin surface) committed the rule, then an `admin_actions` row, then a best-effort audit row whose result was ignored; the review action wrote its audit row before the rule. A storage failure in between left a rule in force with no audit row, or an audit row for a rule that was never stored. The rule, its `admin_actions` row and its audit row are now one transaction, as account moderation has been since ADR-0629, and a store that cannot write all three refuses the change with 500.

### An exclusive alias namespace also blocks deletion (ADR-0688)

An application service's exclusive alias namespace stopped other users and services creating an alias in it but not deleting one: the alias's creator, a moderator of its room or a server administrator could remove a bridge's reserved alias with `DELETE /directory/room/{roomAlias}`. The delete is now refused with 400 `M_EXCLUSIVE` for everyone but the owning application service, as the Application Service API says ("prevents humans and other application services from creating/deleting entities in that namespace"), with no administrator exemption, as for creation.

### A user at their media quota learns nothing about other users' files (ADR-0689)

The per-user byte quota was checked only when an upload stored a new blob, so a user who had filled their quota got 200 for bytes the server already held and a quota refusal for bytes it did not, which confirmed that a known file was stored. The quota is now charged for every upload, a deduplicated one included, so a refusal no longer depends on what other users have stored. The server-wide byte limit still lets a file the server already holds pass (it adds no bytes), and the small timing difference of a deduplicated upload is not changed.

### Evicting from the thumbnail cache no longer scans it (ADR-0690)

Making room in the in-memory thumbnail cache searched every entry for the least recently used one, once per entry evicted, with the global lock held; a client could fill the cache with many tiny thumbnails of one image (every requested size is a separate entry) and then request one large thumbnail. The cache now keeps a recency index, so an eviction costs a logarithmic step, and holds at most 16,384 entries as well as its byte budget.

## 1.0.0

Merovingian 1.0.0 is the first production release. It follows the release-gate security audit (run 2, at commit
279d4a0b): 39 confirmed findings (8 high, 14 medium, 15 low, 2 informational) and 3 that needed validation, all fixed in
0.12.91 to 0.12.93.

### Known limitations

* There is no Complement evidence. 1.0.0 is tagged without a green Complement run. The owner waived that blocker for this
  release only (ADR-0648). Later releases follow `docs/release-process.md` as written.
* SSO login can start, but no route completes it: `complete_sso_login` has no caller. SSO cannot be used.
* `POST /account/deactivate` ignores `erase`.
* The aarch64 branch of the seccomp filters was not run on a real kernel.
* No pre-1.0 database is supported. One from a build up to 0.12.46 is refused at startup. One from 0.12.47 to
  0.12.93 passes the startup check, but the v1 schema changed until it was frozen at 1.0.0, so it may lack columns
  and indexes this build uses.
* The release signing key is read through the `release` environment. The repository owner must restrict that
  environment to `main` and `v*` tags and hold the GPG secrets in it. Until then repository secrets remain readable by
  it.

### Release workflow

* `release.yml`: the hardened Linux tarball job now installs `libcurl4-openssl-dev`. The first `v1.0.0` run failed on
  `missing pkg-config module: libcurl` and published nothing. The fix keeps the version at 1.0.0, and the `v1.0.0` tag
  moves to the fix commit; the owner made this exception to the bump policy for this fix only (ADR-0651).
* `tests/tooling/test_release_workflow.py`: the Linux and FreeBSD release jobs must install a package for every
  pkg-config module their build script checks, so a missing one fails on the pull request, not on the tag.
* `tests/tooling/test_expected_skips.py`: a build script named in a workflow comment no longer counts as a test run
  that needs `--skip-job`, and a `--skip-job` that appears only in a comment no longer satisfies the check.

### Documentation

* `docs/versioning.md`: the scheme from 1.0.0 is `MAJOR.MINOR.BUILD`. `BUILD` is bumped once per branch as `PATCH` was.
  `MINOR` and `MAJOR` change only when the owner decides. The 0.x rules are kept as a short history note. A tag now
  publishes a full release from 1.0.0 (ADR-0647, which supersedes ADR-0047).
* `docs/release-process.md` and `docs/todos/production-milestone.md`: the Complement blocker is waived for 1.0.0, not
  closed, and stays open for later releases (ADR-0648).
* `README.md`, `docs/index.md` and `docs/user-manual.md`: the beta notices now say that 1.0.0 is the first production
  release and point to the known limitations.
* `SECURITY.md`: the latest 1.x release is supported; 0.x releases are not.
* `migrations/AGENTS.md`, `src/database/AGENTS.md`, `docs/database-persistence.md`, `docs/release-process.md` and
  `tests/fixtures/upgrade/README.md`: the v1 schema is frozen now, and a schema change is a new numbered migration.
  `docs/release-process.md` now says which pre-1.0 databases are refused at startup (those up to 0.12.46, by the
  schema ledger check), and that later ones pass it without being supported.
* `docs/todos/production-milestone.md` no longer gives a tag date before the tag exists.
* `packaging/` RPM spec descriptions and the FreeBSD manifest no longer call the project beta.
