Changes from 1.0.0, the first production release, onwards; the format is set out in `docs/versioning.md`
([ADR-0741](docs/adr/0741-each-changelog-version-has-features-security-fixes-bug-fixes-and-release-notes.md)).
Changes before 1.0.0 are in [CHANGELOG-pre-release.md](CHANGELOG-pre-release.md), which is no longer added to
([ADR-0740](docs/adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).

# Version 1.0.2

## Features

* `server.http.client_outbound_max_per_client` sets how many remote calls one client address may have in flight,
  1..128, never above `request_threads / 2`. The default is 3, up from a fixed 1 (ADR-0751).
* Agents review changes with `.agent/skills/merovingian-review/`, which checks module invariants, past defect classes,
  tests and the CHANGELOG, docs, ADR and version obligations, citing the binding docs (ADR-0754).
* `python build.py vm` builds and tests on a Linux or FreeBSD VM over ssh, sending only changed files; it copies
  `testlog.txt` back to `build-vm/`. `scripts/remote-host-setup.sh` prepares the VM (ADR-0752).
* `python build.py vm --vm <name>` uses the `[vm.<name>]` settings and `build-vm-<name>/`, so one machine can drive a
  Linux VM and a FreeBSD VM.
* `--jobs <n>` on `build-linux.sh`, `build-bsd.sh`, `build.py linux` and `build.py bsd` caps compile jobs and tests.

## Security Fixes

* None: every fix below keeps the audit fix it touches. Each one is narrowed to the case the spec requires, and is
  covered by tests that cover the refusal as well (ADR-0745 to ADR-0751).

## Bug fixes

* A first join into a restricted room stores the resident's co-signature, verified exactly as for a join through
  another resident, so it is no longer refused as unauthorised; an invalid one is still refused (ADR-0745).
* A first federated join stores the join's signatures in its `event_signatures` rows as well as its JSON, the
  co-signature of a restricted join included; they were left empty, so a worker's snapshot had none (ADR-0745).
* A threaded receipt is accepted for an event whose relation chain reaches the thread root within 3 hops, such as a
  reaction to a reference of the root (ADR-0746).
* A remote user who is joined, invited or knocking can leave, or reject an invite, through this server after its last
  local member has left; strangers are still refused (ADR-0747).
* A federation read of a room, such as `/event_auth`, is answered by main while the worker is reloading the room, so
  an event sent a moment ago is no longer reported as missing (ADR-0748).
* Outbound federation delivery never reuses a cached discovery failure, so a queued message reaches a server at the
  first retry after it comes back, including after this server restarts (ADR-0749).
* The Complement image allows cleartext appservice URLs on `localhost`, where a Complement blueprint registers one;
  the server's own rule and default are unchanged (ADR-0750).
* Tests name their scratch files uniquely and check each write, so a second account or a concurrent run on the
  same machine no longer reads another run's leftover appservice registration and fails (ADR-0753, ADR-0755).
* Two Complement tests whose expectations contradict the spec are expected failures in the skip list: an MXC-only
  `avatar_url` (F-63, ADR-0406) and an omitted `end` at the start of a room (ADR-0470).
* `build.py linux --hardening` and `build.py bsd --hardening` work: both build scripts used to refuse the option they
  were passed.
* The live-binary startup test runs as a non-root user on the BSDs too: off Linux it accepts the unsandboxed worker,
  as the startup hardening gate does (ADR-0041). It used to fail there.
* The default-summary smoke test is skipped, not failed, on a host with an installed system config, which the server
  reads instead of its defaults.

## Release notes

1.0.2 fixes the Complement regressions that followed the 1.0.1 security audit fixes. No configuration change is
needed. A remote member's own leave is now admitted in a room with no local member, which ADR-0591 had refused.
One client address may now have three remote calls in flight instead of one; set
`server.http.client_outbound_max_per_client=1` to keep the old limit. Windows developers can build and test on a
Linux or FreeBSD VM with `python build.py vm` instead of WSL.

# Version 1.0.1

## Features

* The BSD packages install `config/merovingian.conf.bsd.example`, a BSD edition of the example config: secret files
  under each package's own configuration directory and the SQLite path in `/var/db/merovingian` (ADR-0738).
* CI builds and tests RHEL 10, openSUSE Leap 16 and Tumbleweed, Fedora 44 and 45, Ubuntu 26.04 and 26.10, Debian 13,
  FreeBSD 15, OpenBSD and NetBSD, each image pinned by release, never `rolling` or `latest` (ADR-0742).
* `latest` and every tag ship the same x86_64 packages, built by `packages.yml`, hardened and named for their platform
  (`-debian13.deb`, `-freebsd15.pkg`, `.tumbleweed`, ...); Debian 12 is not packaged (ADR-0742).
* CI joins the runner queue in three tiers: analyses, then build and test jobs, then package jobs (ADR-0743).

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
* The reset-mail daily cap test waits for each background send to end, so a slow host no longer hits the cap of eight
  sends in flight and leaves a session without a code.
* The sync row-index tests prove a counter rose by comparing it, not by an unsigned difference compared to zero, which
  can only test inequality and would wrap if the counter fell.
* The commit-window test waits out the server's background writes when it reads the database, and fails on a read
  error instead of taking it for a missing row; under ASan a busy read made it report no topic at all.
* The RPM specs build with `--buildtype=release`, as every other package does, and their comment escapes `%%meson`,
  which RPM expands even on a comment line.
* `SHA256SUMS` names each asset as published, not `packages/<file>`, so `sha256sum --check --ignore-missing` checks
  the downloaded files instead of none.
* The Complement publisher attaches the tested `-debian13.deb` as `-debian.deb`, beside the tag's own Debian build,
  and refuses a package name without a Debian release number.
* The static tarball's install steps put the federation worker in `/usr/libexec/merovingian`, the path the `/usr`-prefix
  build looks in, not `/usr/local/libexec`; `release-process.md` lists what the tarball holds.
* CI checks the signer and source ref for the tagged and rolling release instructions, and the join test checks that
  the client-outbound slot is released after the `make_join` worker finishes.
* The attestation recipe check skips local dot-directories, such as other worktrees, which CI never has.

## Release notes

1.0.1 fixes the 49 confirmed findings of the security audit of the 1.0.0 release candidate (run 3, at d9b93005; nine
high, all availability) and hardens two of the four findings that needed validation. **Upgrade:**
`federation.worker.database_uri_file` and `federation.worker.allow_shared_database_credentials` are now refused at
start-up, so remove them from a PostgreSQL deployment first; the worker's database role can then be dropped
(ADR-0736). The changelog now starts at 1.0.0 and uses the format in `docs/versioning.md` (ADR-0740, ADR-0741). A
tag now ships exactly the `latest` package set (ADR-0742).

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
