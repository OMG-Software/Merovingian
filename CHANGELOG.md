Changes from 1.0.0, the first production release, onwards; the format is set out in `docs/versioning.md`
([ADR-0741](docs/adr/0741-each-changelog-version-has-features-security-fixes-bug-fixes-and-release-notes.md)).
Changes before 1.0.0 are in [CHANGELOG-pre-release.md](CHANGELOG-pre-release.md), which is no longer added to
([ADR-0740](docs/adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).

# Version 1.0.1

## Features

* The BSD packages install `config/merovingian.conf.bsd.example`, a BSD edition of the example config: secret files
  under each package's own configuration directory and the SQLite path in `/var/db/merovingian` (ADR-0738).

## Security Fixes

* The federation worker opens no database on either backend: main sends it the rows it reads, each room only under a
  permit main issued, so a taken-over worker can no longer block main's writes (C44, ADR-0733 to ADR-0736, ADR-0739).
* An IPC frame that cannot be written whole ends the channel, so the supervisor replaces the worker instead of keeping
  one whose stream is broken (ADR-0734).
* A spawned worker no longer shares the server's terminal: its seccomp profile kills `TIOCSTI` and `TIOCLINUX`, and it
  runs in its own session with `/dev/null` as stdin (NV-1, ADR-0731).
* The documented release provenance check pins the release workflow and the tag, so an attestation made by a branch or
  pull-request run no longer passes it (NV-2, ADR-0732).
* One client address can no longer fill the pending-connection budget, and a readable connection waits a bounded time
  for a worker (C01, ADR-0719).
* A slow federation destination can no longer hold the outbound queue and every delivery thread (ADR-0720), and a slow
  push gateway no longer holds the delivery reserve (ADR-0721).
* One event's push badges share one rule-evaluation budget, and push rule key paths are charged to it (ADR-0722,
  ADR-0723).
* A directory search parses a bounded number of bytes (ADR-0724).
* Abandoned `make_join` candidates stop making calls, use few threads and keep holding the client's slot (ADR-0725).
* `POST /delete_devices` is capped and finds devices by index (ADR-0669).
* A client key claim is capped and merges a remote answer in linear time, and a key query reads the user's device keys
  by index (ADR-0670, ADR-0671).
* Key signature uploads commit in one transaction and use indexes (ADR-0672).
* A key backup's etag no longer rehashes the whole backup, and a backup session has a size limit (ADR-0673).
* A device's to-device queue is shared out per sender (ADR-0674).
* A backfilled event is recognised as stored by index, and an `/event_auth` answer is capped (ADR-0705).
* A remote join no longer re-sends every local device list (ADR-0706).
* Remote invites are capped in bytes per sending server and in all, and a user's knocks are capped in bytes (ADR-0707,
  ADR-0708).
* A resident server's membership template can no longer add content that this server then signs (ADR-0709).
* A remote server can no longer get `unsigned` past the strip with an escaped key (ADR-0710).
* Federation reads of main's store hold the runtime lock, and main answers federation hierarchy requests (ADR-0711,
  ADR-0712).
* Choosing a signing key no longer copies every cached remote key (ADR-0713).
* Composing an event reads its own room's state by key instead of walking every room's state (C35).
* State resolution reads each auth event once instead of copying and searching it per conflicted event (ADR-0693).
* The state before an event is resolved and stored once per distinct set of prev groups (ADR-0694).
* Senders without power share one cap on a room's forward extremities,
  `security.federation.state_resolution.max_unprivileged_state_tips` (default 128) (ADR-0695).
* A federated state event's commit no longer lets a local write in between, so memory and the database cannot disagree
  on a room's current state (ADR-0696).
* A room's state revision moves after its state row is written, so a cached `send_join` plan cannot serve superseded
  state (ADR-0697).
* A federated join commits its answer, auth chain and members in a few transactions, writing the auth chain with the
  runtime lock released (ADR-0714).
* A sliding sync connection keeps a bounded number of bytes, and a room timeline stops after a fixed number of rows it
  does not take (ADR-0663, ADR-0664).
* Sliding sync list filters and the notification sort no longer scan whole tables per room (ADR-0665, ADR-0666).
* Receipts are indexed by room and user, a threaded receipt must belong to its thread, and a receipt EDU commits in one
  transaction (ADR-0737, ADR-0652).
* The ACL checks of one request share a step budget (ADR-0653).
* Classic sync reads each room's own rows, and a room past the room cap still gets its news (ADR-0654, ADR-0658,
  ADR-0659).
* Unread counts parse a bounded number of bytes, and `/context` and `/initialSync` stop at an examination budget
  (ADR-0655, ADR-0656).
* A sync filter's lists are capped at 100 entries (ADR-0657).
* OpenID tokens are looked up by hash and capped at 32 per user (ADR-0681, ADR-0682).
* One user can no longer void another user's user-interactive authentication session (ADR-0683).
* The validation session cap counts per client, not per reverse proxy (ADR-0684).
* The owner of an address can always use a password reset code, however many sessions others open for it (ADR-0685).
* Reporting no longer reads the audit log and is limited per user (ADR-0686).
* A policy rule change and its audit row commit together (ADR-0687).
* An application service's exclusive alias namespace also blocks deleting an alias in it (ADR-0688).
* A user at their media quota learns nothing about which files other users have stored (ADR-0689).
* Evicting from the thumbnail cache no longer scans it under the global lock (ADR-0690).

## Bug fixes

* The keep-alive cap test no longer aborts the BSD integration test binaries, and the IPC write-failure test holds on
  NetBSD and OpenBSD.
* The federation worker test no longer passes its open-descriptor check without looking when `/proc/<pid>/fd` cannot be
  read; it skips visibly there.
* The snapshot reader pool test now builds on FreeBSD and OpenBSD: it used `std::jthread`, which their libc++ lacks.
* The stale-ACL worker test fails main's room snapshot read by hiding a table, not the database file, which the
  readers opened at start keep open (ADR-0739).
* The C44 worker test finds the worker on NetBSD by `ps -o ucomm`: `comm` is the worker's full path there, cut at 79
  columns; it lists the children it saw when the count is wrong.

## Release notes

1.0.1 fixes the 49 confirmed findings of the security audit of the 1.0.0 release candidate (run 3, at d9b93005; nine
high, all availability) and hardens two of the four findings that needed validation. **Upgrade:**
`federation.worker.database_uri_file` and `federation.worker.allow_shared_database_credentials` are now refused at
start-up, so remove them from a PostgreSQL deployment first; the worker's database role can then be dropped
(ADR-0736). The changelog now starts at 1.0.0 and uses the format in `docs/versioning.md` (ADR-0740, ADR-0741).

# Version 1.0.0

## Features

* Versions from 1.0.0 are `MAJOR.MINOR.BUILD`, and a `v*` tag publishes a full release (ADR-0647).

## Security Fixes

* None in this version: the fixes of the release-gate security audit (run 2, at 279d4a0b) shipped in 0.12.91 to 0.12.93.

## Bug fixes

* `release.yml` installs `libcurl4-openssl-dev` in the hardened Linux tarball job; the first `v1.0.0` run had failed
  and published nothing. The `v1.0.0` tag moved to the fix without a version bump (ADR-0651).
* The release workflow test requires each release job to install a package for every pkg-config module its build
  script checks, and the expected-skips test no longer counts a `--skip-job` that appears only in a comment.

## Release notes

Merovingian 1.0.0 is the first production release. Known limitations: it was tagged without a green Complement run (a
waiver for this release only, ADR-0648); SSO login cannot complete; `POST /account/deactivate` ignores `erase`; the
aarch64 seccomp filters were not run on a real kernel; no pre-1.0 database is supported (one from 0.12.46 or earlier is
refused at start-up); and until the owner restricts the `release` environment to `main` and `v*` tags, repository
secrets remain readable by it. Only the latest 1.x release is supported (`SECURITY.md`).
