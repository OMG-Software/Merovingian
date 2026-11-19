Changes from 1.0.0, the first production release, onwards; the format is set out in `docs/versioning.md`
([ADR-0741](docs/adr/0741-each-changelog-version-has-features-security-fixes-bug-fixes-and-release-notes.md)).
Changes before 1.0.0 are in [CHANGELOG-pre-release.md](CHANGELOG-pre-release.md), which is no longer added to
([ADR-0740](docs/adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).

# Version 1.1.3

## Features

* MatrixRTC calls on LiveKit need no `lk-jwt-service`: `POST .../rtc/livekit/get_token` (MSC4195) issues tokens to
  joined users; `server.rtc.livekit.url`, `api_url`, `api_key` and `api_secret_file` turn it on (ADR-0829, ADR-0830).
* A token for another server's SFU is relayed to it over federation, and other servers' joined users get subscribe-only
  tokens for this server's SFU, judged by the main process and refused to a server the room's ACL denies (ADR-0831).
* `delegate_delayed_leave` (MSC4195): this server sends a caller's delayed leave once LiveKit no longer shows them,
  checked every 30 s and sooner on LiveKit's signed webhook, kept across restarts (ADR-0832, ADR-0833).
* A branch no longer bumps the version: it changes only when the owner asks, and a change adds its bullets to the
  newest version's entry here (ADR-0835).
* A pull request runs a core CI gate (Ubuntu, FreeBSD and the analyses); the other platforms and every package run
  in the merge queue before a merge, as skipped checks on the pull request (ADR-0840).
* A new push to a pull request cancels the runs for its previous head; other events are never cancelled (ADR-0842).
* The integration tests run as four parallel Catch2 shards, with `[postgresql]` and `[serial]` scenarios kept apart
  and a check that the shards together run every scenario once (ADR-0845).
* CI workflows can be started by hand on a branch with no pull request (`workflow_dispatch`) (ADR-0841).
* Sticky events (MSC4354): `PUT /send` and delayed events take `org.matrix.msc4354.sticky_duration_ms` (or
  `sticky_duration_ms`), sticky for up to an hour; `/versions` lists `org.matrix.msc4354` (ADR-0853).
* `/sync` serves every unexpired sticky event in `sticky` and `msc4354_sticky`, sliding sync in the `sticky_events`
  extension (MSC4480), each once per connection (ADR-0855, ADR-0857, ADR-0858).
* Every joined user and server may read an unexpired sticky event on any endpoint, whatever the room's history
  visibility (MSC4354); the federation worker gets the sticky rows in its room snapshots (ADR-0858).
* Sliding sync sends sticky senders' member events with lazy-loaded members, and the extension reads MSC4508's `lists`
  and `rooms` scope; an event that expires mid-request is left out (ADR-0858).
* Sliding sync's `typing` and `receipts` extensions read MSC4508's `lists` and `rooms` as `sticky_events` does; a room
  named in `rooms` without a subscription is no longer served (ADR-0861).
* A server that joins a room is sent this server's unexpired sticky events in it, and accepted sticky events from other
  servers are served like local ones (ADR-0856).
* `server.sticky_events.enabled` (on), `max_per_sender` (60) and `max_per_room` (1000) configure them; migration 005
  adds `sticky_events` and `delayed_event_sticky_durations` (ADR-0854, ADR-0857).
* The Linux packages set up a LiveKit SFU you install beside the server: a `merovingian-livekit` account and disabled
  service, `merovingian-livekit-setup` for the shared key, and `livekit.yaml.example` (ADR-0860).

## Security Fixes

* LiveKit tokens are HS256, signed only by typed functions that cannot grant room creation, administration or hidden
  participants; the API secret is read per token and never logged (ADR-0828).
* LiveKit's webhook is believed only when signed with the API secret for its exact body and recent, and even then only
  brings a check forward: it never sends or restarts an event (ADR-0833).
* The federation worker refuses to start if a Landlock rule would let it read the LiveKit API secret file (ADR-0062).
* The packaged LiveKit SFU never runs as `merovingian`, has no capabilities, and gets the API secret in a file of its
  own; the setup helper never prints the secret, passes it in argv or replaces a file (ADR-0860).
* A LiveKit call's host lookup counts against the call's deadline: the exchange gets only the time the lookup left,
  and none starts once the deadline has passed (ADR-0830).
* A sticky event's hour starts when this server first saw it, or earlier if its timestamp says so: neither a remote
  server nor an application service's `?ts=` can extend it (ADR-0854).
* A sender, local or remote, keeps at most `max_per_sender` unexpired sticky events; one more expires their oldest, so
  one user cannot grow the table or every room's sync without bound (ADR-0854).
* A room keeps at most `max_per_room` unexpired sticky events; one more expires the oldest of the server holding the
  most, so a server flooding a room displaces only its own, never another server's call memberships (ADR-0857).
* A client's sticky duration above 2^53-1 is refused, so a composed event stays canonical JSON (ADR-0853).
* A joining server that the federation policy or the room's ACL denies is sent no sticky events, and only events this
  server sent and still holds in that room are ever pushed (ADR-0856).
* A redaction whose target has not been received is never sent as a sticky event: the sticky exemption skips history
  visibility only (ADR-0862).
* A sticky event that expires a sender's row in another room refreshes the federation worker's snapshot of that room,
  so the worker stops serving the removed event (ADR-0862).

## Bug fixes

* The openSUSE package now runs `%systemd_pre`, so the host's systemd preset policy applies to `merovingian.service` on
  install as it does on Fedora and RHEL; without it openSUSE never applied the policy.
* `use_state_after`: a room forked at `since` now gets exactly what changed since what the client was told, read from an
  in-memory log of state changes, and so does a left room (ADR-0827).
* SQLite writes share one connection, whatever `database.pool_size` says: a second write connection waited for the
  first's lock by polling, lost to its back-to-back commits and was refused after 5 s, failing the write (ADR-0834).
* ccache now caches compiles in CI: the jobs restored a cache but compiled without it, so it stayed empty; only `main`
  writes the cache (ADR-0843).
* `claude/**` and `codex/**` pushes no longer run every workflow a second time beside their pull request (ADR-0841).
* The NetBSD jobs fetch and verify their packages on the CI host and cache them, instead of paying a three-minute
  mirror stall per package inside the VM (ADR-0844).
* Coverage and the SonarQube Cloud scan share one instrumented build; Codecov uploads from a job of its own, away from
  the Sonar token (ADR-0846).
* The ThreadSanitizer job fails when its build or tests fail: the step piped into `tee` without `pipefail`, so it
  reported `tee`'s success.
* clang-tidy runs on pull requests: a failed diff on the shallow checkout read as no changed files. It now checks the
  lines a change adds or edits, and a push to main checks the commits it added (ADR-0847).
* clang-tidy gets 15 minutes per file and 60 for the job: the largest test files outran the first limit of two
  minutes on a busy runner, and a file the timeout killed failed the check with no finding (ADR-0847).
* The NetBSD package fetcher matches NetBSD's version order, uses only a summary holding every required package and
  moves to the next mirror on a bad file; the guest tries the cached packages alone before any mirror (ADR-0844).
* A failed Codecov upload fails the `codecov` job instead of the required `coverage` check; its report is kept 30 days
  so the job can be re-run alone (ADR-0846). `coverage.yml` grants its permissions per job, none to the workflow.
* Every action the `codecov` job runs is pinned to a commit, since the job holds `CODECOV_TOKEN`; its artifact
  download was a tag.
* PDU ingestion refuses a caller that holds the runtime lock: it would take the room's lock in the reverse order and
  could deadlock against an ingest of the same room (ADR-0848).
* SRV lookups on glibc each own their resolver state, set up and torn down under a lock that ThreadSanitizer can see;
  the query itself stays unlocked (ADR-0849).
* Tests no longer read what a mock server's thread recorded before joining it, count concurrent discovery calls
  atomically, and keep Catch2 assertions off mock threads, so the `tsan` job reports no races.
* The mlock and forked-task-count scenarios skip under ThreadSanitizer, as the mlock ones already did under ASan:
  TSan's own interceptor and background thread make what they check unobservable.
* The decoder seccomp filter's forked children skip under TSan, whose background thread the filter kills for sleeping,
  so a child that made only allowed calls no longer fails the `tsan` job at random (ADR-0852).
* A sliding sync long poll is no longer answered with nothing by a typing or receipt change outside the extension's
  scope (ADR-0861).
* A sliding sync long poll now wakes when the user's own receipt reorders a list sorted by notification count
  (ADR-0861).
* A sliding sync long poll now wakes when the user's own tag or `m.direct` moves a room into a filtered list
  (ADR-0861).
* A room entering the sliding sync typing scope now gets who is typing there, and a room back in the receipts scope
  the receipts that changed while it was out (ADR-0863).
* A slower package run of an older `main` commit no longer replaces a newer `latest`, nor does a run `main` dropped:
  publishes run one at a time, and each must be on `main` and equal or descend from the `latest` tag (ADR-0850).
* Publishing `latest` moves its tag instead of deleting it, so a failed publish can no longer let an older queued build
  replace a newer one (ADR-0850).
* The scenarios that race a request against a password hash pause the hash until the other request is made, so a slow
  runner can no longer make them fail, or pass without testing the race (ADR-0851).
* The test-only local router runs inbound federation without `runtime.mutex`, as the server does, so its PDU sink no
  longer refuses every transaction's PDUs for a held lock (ADR-0848).
* The directory, profile, device keys, user devices and one-time-key claim federation providers take `runtime.mutex`
  themselves, as the other store readers do, so main never reads its store unlocked through them (ADR-0711).
* A sliding sync sticky backlog larger than `limit` is delivered over several responses when no stream advances: such
  a response's `pos` carries a page, so the next request acknowledges it rather than reading as a retry (ADR-0862).
* A lazy-loading `/sync` sends a sticky-only sender's member as of the timeline's start, or as of the response when that
  state has none, rather than at the oldest sticky event (ADR-0862).
* Sliding sync lists now hold the rooms a user is invited to, with `invite_state` only and sorted by the invite's
  position, and a new invite (createRoom or `/invite`) that a list or a room subscription could hold ends a waiting
  long poll at once (ADR-0864).
* A rejected or withdrawn invite now wakes the invitee's sliding sync long poll and leaves the list; an accepted one is
  sent as a new joined room (ADR-0864).
* Any change of a user's own membership other than a new invite answers their sliding sync long poll, so an invite
  withdrawn outside every window updates the list's count; a new invite answers it only if a room subscription names
  its room or a list's filters hold it.
* A sliding sync response that reports an invite at an unchanged position carries a new page, so the next request
  acknowledges it rather than receiving the invite again; the connection records the invite at its own position, so
  an invite stored while another write is still committing is not sent twice (ADR-0864).
* A parked sliding sync long poll judges a new invite against its lists' filters from the user's own membership rows,
  never a pass over every room the server holds (ADR-0665).

## Release notes

Version 1.1.3 is in progress: a LiveKit token service built into the server for MatrixRTC calls, with delegated leaves,
an exact `state_after` on `/sync`, and sticky events (MSC4354) for Element Call. It adds migrations 004
(`livekit_delegations`) and 005 (`sticky_events`). After a restart, the first `state_after` sync of each room with news
carries its whole state once. A SQLite server no longer refuses writes under sustained write load, and
`database.pool_size` now applies to PostgreSQL only. CI now runs a core gate on a pull request and the full matrix in
the merge queue: turn the merge queue on in the "Protect main" ruleset, or pull requests merge after the core gate
alone.

# Version 1.1.2

## Features

* Delayed events (MSC4140): schedule, restart, cancel, send and look up one, on the v1.20 paths, the
  `org.matrix.msc4140` paths and `?org.matrix.msc4140.delay=` on `/send` and `/state` (ADR-0823).
* `/versions` and `/capabilities` advertise delayed events (`org.matrix.msc4140`, `m.delayed_events`)
  (ADR-0823).
* A due delayed event is sent by the server as its user through the ordinary send path: authorised when sent,
  never early, kept across a restart (ADR-0825).
* Migration 003 adds the `delayed_events` table; finalised events are kept per user up to a bound and 7 days
  (ADR-0824).
* `server.delayed_events.enabled`, `max_delay_ms`, `max_scheduled_per_user` and `max_finalised_per_user`, with
  built-in per-user rate limits (ADR-0826).

## Security Fixes

* None.

## Bug fixes

* None.

## Release notes

Delayed events for MatrixRTC, on top of 1.1.1. 1.1.2 migrates the database: on first start it applies migration 003,
which adds one empty table and changes no existing one. A 1.1.1 or older server refuses the migrated database, so
back it up before upgrading if you may need to go back. The feature is on by default; setting
`server.delayed_events.enabled = false` and restarting stops new scheduling, while events already scheduled are still
sent and can still be managed. Operators running Element Call keep `max_delay_ms` at 3600000 or more.

# Version 1.1.1

## Features

* `GET /_matrix/client/v3/sync` honours `use_state_after` (Matrix v1.16): with it true each joined and left room
  carries `state_after` and no `state` (ADR-0818, ADR-0819, ADR-0820).
* The cross-release upgrade fixture `tests/fixtures/upgrade/1.0.3/`, written by the 1.0.3 release, is opened, taken
  through migration 002 and served on SQLite and PostgreSQL by the `[fixture]` scenarios (ADR-0216).
* MatrixRTC transport discovery (MSC4143): `server.rtc.livekit.service_url` is advertised as a `livekit` transport
  on `/rtc/transports`, `/versions` and the well-known document (ADR-0822).
* `server.turn.uris` lists several TURN URIs for `GET /voip/turnServer`, in order; `server.turn.server` still works and
  both together are refused (ADR-0821).
* The `use_state_after` scenarios asserting project choices, not spec rows, moved from the conformance suite to
  `tests/integration/test_sync_state_after_flow.cpp`.

## Security Fixes

* None.

## Bug fixes

* `use_state_after`: the state anchor at `since` is a binary search of the room's index, so a client back after a long
  absence no longer walks every row it missed under the runtime lock.
* `use_state_after`: a room joined and left inside one sync window now gets its whole readable state as of the leave in
  `state_after`, not a delta that hid the create event, power levels and join rules (ADR-0820).
* The sync row of `docs/todos/capability-gaps.md` no longer says a limited sync gives no gap state, and tracks the
  `state_after` limit after a state fork (ADR-0819).
* Tests: the upgrade fixture scenarios prove the 1.0.3 sync token stays incremental and its epoch survives
  migration; scratch files are uniquely named; a missing JSON field fails one scenario, not the binary.

## Release notes

1.1.1 adds `use_state_after` to `/sync`, `server.turn.uris` and MatrixRTC transport discovery. The new keys
(`server.turn.uris`, `server.rtc.livekit.service_url`) are optional; no configuration change is needed. Group calls
still need your own LiveKit SFU and `lk-jwt-service`, and delayed events (MSC4140) are not implemented. Known limit
of `use_state_after`: after a state fork at the client's `since`, a key that state resolution later flips back to the
value recorded at `since` is not sent in `state_after`; a client repairs itself with `full_state=true` (ADR-0819).

# Version 1.1.0

## Features

* A built-in OAuth 2.0 API, which Element X needs to create accounts, planned in `docs/todos/oauth-2-0-api.md`
  (ADR-0812 to ADR-0816).
* Strict form-body and `Cookie` header readers and a `__Host-` `Set-Cookie` builder in `core`, which the OAuth 2.0
  pages and endpoints read and write with (ADR-0817, ADR-0766).
* A module `oauth` of pure OAuth 2.0 building blocks the endpoints call: PKCE `S256` and the scope parser
  (ADR-0768, ADR-0769).
* A strict URI reader, redirect URI rules with byte-exact matching, and RFC 7591 client metadata validation with a
  canonical form (ADR-0770, ADR-0771).
* The one HTML page renderer, which accepts only escaped text, and the headers every page carries (ADR-0772).
* `crypto::sha256` for protocols that name SHA-256.
* `server.oauth.enabled` serves the OAuth 2.0 server metadata at `auth_metadata` and its MSC2965 path; off, both
  answer 404. The issuer is `server.public_baseurl`, endpoints sit under `/_merovingian/oauth2/` (ADR-0773, ADR-0775).
* `server.oauth.legacy_api_enabled`, `server.oauth.device_grant_enabled` and `server.oauth.hand_off_redirect_allowlist`
  (https origins or bare private-use schemes, never prefixes) are parsed and checked; all need a restart (ADR-0774).
* With OAuth on, `server.public_baseurl` must be an https URL with a host and no query, and
  `server.sso.authorization_url` is refused.
* Migration 002 adds the `oauth_clients` and `oauth_sessions` tables, hydrated on both backends; deleting a device
  deletes its OAuth session in the same transaction (ADR-0776, ADR-0778).
* The retention sweep deletes OAuth clients with no session unused for 30 days, never one with a session, and a
  client's last use is written at most once a day (ADR-0777).
* `POST /_merovingian/oauth2/register` registers OAuth 2.0 clients (RFC 7591); the client ID is a keyed hash of the
  accepted metadata, so a repeat registration is the same client (ADR-0779, ADR-0781).
* At most 10000 OAuth clients are held: at the cap idle ones go least recently used first, else 503 (ADR-0780).
* `/_merovingian/oauth2/*` and `/_merovingian/account*` take the `auth_sensitive` rate limit; `201 Created` has its
  reason phrase.
* In-memory, hashed, bounded OAuth 2.0 pending authorisations and authorization codes that never evict a live entry;
  the sweep and the client cap keep a client that holds one (ADR-0782).
* The password check of `POST /login` and the account creation of `POST /register` are each one function, shared
  with the OAuth 2.0 pages; both routes answer as before (ADR-0783).
* OAuth 2.0 pages send `Referrer-Policy: same-origin`, get no CORS headers, and accept a form post only from this
  server's origin (ADR-0784, ADR-0785).
* `GET` and `POST /_merovingian/oauth2/authorize` serve the sign-in, account creation and consent pages and send the
  browser back to the client with an authorization code or an error (ADR-0787, ADR-0789).
* Every OAuth authorisation asks for the password; a sign-in is bound to its browser by a `__Host-` cookie and the
  form's pending identifier, at most 16 in progress per address (ADR-0787, ADR-0788).
* An approval judges the account again, is audited, and its redirect sends no referrer; it creates no device, token
  or OAuth session (ADR-0790).
* `POST /_merovingian/oauth2/token` serves the code grant (PKCE, exact redirect URI, one transaction) and the
  refresh grant, for public clients only; an OAuth access token always expires (ADR-0791, ADR-0792).
* `POST /_merovingian/oauth2/revoke` ends the session of an access or refresh token as `/logout` does, and answers
  200 for an unknown token (ADR-0795).
* A replayed authorization code ends only the session it produced; `POST /refresh` and the refresh grant each refuse
  the other kind of session, before the token is spent (ADR-0792, ADR-0793).
* Endpoints that ask for User-Interactive Authentication answer an OAuth session `403 M_FORBIDDEN` naming the
  account page; application services are not refused (ADR-0794).
* `GET` and `POST /_merovingian/account` serve the account pages: sign-in, devices, device sign-out, password
  change, deactivation and cross-signing reset approval, with all six spec actions advertised (ADR-0796).
* An account-page session lives a fixed 15 minutes in memory behind a strict `__Host-` cookie and a form token; its
  sign-in shares the `POST /login` throttle (ADR-0796).
* An OAuth session replaces its cross-signing keys through the `m.oauth` stage: one approval on the account page,
  valid 10 minutes, spent only by a stored upload (ADR-0797).
* Each account-page action calls the client API's own function; a page password change logs every session out and
  keeps the devices (ADR-0798).
* The `m.oauth` stage accepts a polling retry with no `auth` once approved, reuses the user's live UIA session, and
  also offers its pre-standard name `org.matrix.cross_signing_reset` (ADR-0799).
* A tooling test refuses a default member initialiser holding OAuth page text, which clang 18 checks only at run
  time (ADR-0800).
* `server.oauth.legacy_api_enabled=false` stops legacy logins and registrations; appservices register with
  `inhibit_login`, and sessions already issued carry on (ADR-0801).
* With OAuth on, `GET /login` prefers `m.login.sso`, whose redirect signs in on the built-in pages, confirms, and
  returns a single-use 30-second `loginToken` to `redirectUrl` (ADR-0802).
* `server.oauth.device_grant_enabled` serves the device authorization grant: `POST /_merovingian/oauth2/device`, the
  code page `/_merovingian/oauth2/link` and the device code grant, as RFC 8628 answers it (ADR-0804).
* Device sign-ins are held in memory, 4096 at most and 8 per address; five wrong codes block an address for the rest
  of ten minutes (ADR-0805).
* A device sign-in's consent page warns first that another device is being signed in, never creates an account, and
  one browser at a time answers a code (ADR-0806).
* The threat model and the security review checklist cover the OAuth 2.0 API: its pages, form posts, redirects,
  stores, sessions and logging, with the risks the ADRs accept.
* The OAuth 2.0 plan records phases 1 to 10 as done and lists what is still open: Element X, PostgreSQL and the
  upgrade fixture, QR-code login, the documentation site and `response_mode`.

## Security Fixes

* The query of a `/_merovingian/oauth2/*` or `/_merovingian/account*` request is never logged, so a state, code or
  login hint cannot reach the log (ADR-0786).
* Every password change, reset and deactivation now ends the user's account-page sessions and withdraws a
  cross-signing reset approval (ADR-0798).
* A response header that would frame the message (`Content-Length`, `Connection`, ...) or holds CR or LF now turns
  the response into a 500 instead of being written or silently dropped (ADR-0767).
* A password change, reset or deactivation now ends an OAuth sign-in already past the password, an unredeemed code
  and an unpolled device approval: they are refused, not granted (ADR-0807).
* An OAuth session's row now goes with the last credential of its device (a password change, reset, deactivation,
  refresh-token reuse or expiry), so its client can be evicted or aged out (ADR-0808).
* A cross-signing reset approved on a page that named the asking OAuth device can be used only by that device; the
  `m.oauth` URL now carries `device_id` (ADR-0809).
* A refused OAuth token or device request logs its `client_id` only when it names a registered client, so a caller
  cannot write text of its choosing into the log.
* A client URI host whose last label is a number to a browser (`app.0x7f`, the WHATWG rule) is refused (ADR-0771).
* A client name holding an invisible character (soft hyphen, zero-width characters, word joiner, BOM, tag characters
  and others) is refused, so two names cannot look alike (ADR-0771).
* The legacy SSO hand-off refuses a private-use scheme address with an authority, such as `com.example.app://host/`,
  which an allowlisted bare scheme never named (ADR-0802).
* The URI reader takes an IPv6 host only in the RFC 3986 grammar, not any run of hex digits, `:` and `.` (ADR-0811).

## Bug fixes

* An exception a client-server handler lets escape is answered `500 M_UNKNOWN` instead of closing the connection,
  and its log line names the route and type but never the message (ADR-0803).
* A handler's `Content-Type` spelled in another letter case no longer adds a second `Content-Type` to the response,
  and 302, 303, 409, 504 and other statuses now carry their reason phrase instead of `OK`.
* `merovingian-db-migrate --plan 1 2 --migrations` now plans only the files between the two versions, instead of
  every file in the directory.
* `POST /keys/device_signing/upload` asks for UIA only to change held keys: a first upload or a repeat of the held
  keys succeeds without it, and an application service never needs it, as the spec says (ADR-0794).
* The code grant names the session a replayed code ends before it commits, so no step that can fail follows the
  commit (ADR-0792).
* An exception escaping the authorisation, device link, account or SSO hand-off page is answered with an HTML error
  page under the pages' headers, not JSON (ADR-0810).
* The OAuth refresh grant lists a device after a restart with its stored display name, not its device ID.
* `POST /refresh` now does the same, through the function the refresh grant uses: a device it lists again after a
  restart keeps its stored display name.
* The server builds on FreeBSD again: the exception type name of ADR-0803 now includes `<typeinfo>`, which FreeBSD's
  `cxxabi.h` does not.
* A native client on an `http://[::1]` redirect URI completes its sign-in: CSP cannot name an IPv6 host, so
  `form-action` gets `http:` for it (ADR-0811).
* The hand-off confirmation page shows the destination's port, so two loopback applications are told apart.
* The page queries of `/authorize`, `/link`, `/account` and the SSO redirect read a bare name or an empty field as
  not sent, as RFC 6749 section 3.1 asks, instead of refusing the request (ADR-0817).
* The device and token inserts of a login, a grant and a refresh share one statement each; the SQL is unchanged.
* `POST /register` works again on FreeBSD's 64 KiB locked-memory limit: the OAuth client ID key is derived per
  registration, not locked for life, and an unreadable token file logs `registration.token_file_unusable` (ADR-0779).
* The FreeBSD rc.d script sets the service's locked-memory limit itself (`merovingian_limits`, default `-l 128m`),
  so the room for secrets no longer depends on the login class; `rc.conf` can override it.
* The PostgreSQL role tests remove the whole schema, not only the v1 tables, before they bootstrap it again: the
  tables of migration 002 were left behind and the next open failed creating them.
* The compile-time checks of `HtmlLiteral`, `HtmlName` and `PagePath` throw `std::logic_error`, not a string
  literal, so a check that does run at run time is caught as a standard exception.
* The percent-escape decoders of `FormFields` and `ParsedUri` advance by the bytes each branch read, and
  `ClientMetadata::validate` and `ParsedUri::read` say why each step is there (CodeQL).
* `PendingAuthorisationStore::find` and `record_user` no longer name a hash they do not use; twelve long OAuth
  test scenarios gained comments and three test helpers were tidied (CodeQL).

## Release notes

1.1.0 is in development. A configuration that sets any `server.oidc.*` key is now refused at start-up: remove those
keys and set `server.oauth.enabled` instead (ADR-0816). The authorisation, token and revocation endpoints and the
account pages at `/_merovingian/account` are served; a user signed in through OAuth changes a password, signs out a
device, deactivates the account or approves a cross-signing reset there. The device authorization grant is off by
default; turn on `server.oauth.device_grant_enabled` only if your users sign in devices without a browser. 1.1.0
migrates the database: on first start it applies migration 002, which adds two empty tables and changes no existing
one. A 1.0.x server refuses the migrated database, so back it up before upgrading if you may need to go back.
# Version 1.0.3

## Features

* `docs/release-process.md` and the production milestone record that 1.0.1, like 1.0.0, was tagged without a green
  Complement run, and that the 1.0.0 GitHub release is withdrawn (ADR-0744).

## Security Fixes

* None.

## Bug fixes

* A backfill recovery asks the origin for a listed state event at most once: a later state snapshot listing one the
  origin already refused ends without asking, so it is fetched and logged once, not once per gap (ADR-0760).
* A remote profile lookup for a server that just gave no answer is answered 502 at once for the next 60 s, so client
  lookups to a dead server no longer each hold an outbound slot for the whole deadline (ADR-0761).

## Release notes

1.0.3 cuts repeated federation work and log noise seen on a production server: a refused history event is asked for
once per recovery, and a server that gives no answer to profile lookups is left alone for a minute. No configuration
change is needed. 1.0.1 was also tagged without a green Complement run, and the 1.0.0 GitHub release is withdrawn
because it ships the vulnerabilities 1.0.1 fixes; a 1.0.0 server should upgrade.

# Version 1.0.2

## Features

* `server.http.client_outbound_max_per_client` sets how many remote calls one client address may have in flight,
  1..128, never above `request_threads / 2`. The default is 3, up from a fixed 1 (ADR-0751).
* Agents review changes with `.agent/skills/merovingian-review/`, which checks module invariants, past defect classes,
  tests and the CHANGELOG, docs, ADR and version obligations, citing the binding docs (ADR-0754).
* `python build.py vm` builds and tests on a Linux or FreeBSD VM over ssh, sending only changed files; it copies
  `testlog.txt` back to `build-vm/`. `scripts/remote-host-setup.sh` prepares the VM (ADR-0752).
* `python build.py vm --vm <name>` uses the `[vm.<name>]` settings and `build-vm-<name>/`, so one machine can drive a
  Linux VM and a FreeBSD VM (ADR-0752).
* `--jobs <n>` on `build-linux.sh`, `build-bsd.sh`, `build.py linux` and `build.py bsd` caps compile jobs and tests
  (ADR-0752).

## Security Fixes

* A resident's make_join, make_leave or make_knock template can no longer put signatures or hashes of its choosing
  into this server's membership event; they are dropped before signing, and an unparseable join is refused (ADR-0745).
* Every fix under Bug fixes keeps the audit fix it touches. Each one is narrowed to the case the spec requires, and is
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
* So are a remote user's `make_leave` and `make_knock`, so rejecting an invite a moment after it arrives builds a
  leave that names the invite, and it is no longer refused with 403 (ADR-0759).
* A remote server's join, knock, leave or PDU for a room created a moment ago is served by main until the
  federation worker has loaded the room, so it is no longer refused under a guessed room version (ADR-0756).
* So is a room the worker's start-up copy left out, a room first changed while the worker's channel was down, and a
  whole `/send` transaction when any room it names is one of these, not only its first (ADR-0756).
* Every worker shard now reloads every changed room, and main tracks each shard's copy, so a `/send` naming rooms
  of several shards is judged by one worker on current copies, never sent to main for that (ADR-0758).
* `docs/architecture.md` described the worker's room reload twice, once in a pre-1.0.1 form with a database read; it
  now describes it once, through main, with main's providers under `main_store_read_lock` and `/hierarchy` on main.
* Outbound federation delivery never reuses a cached discovery failure, so a queued message reaches a server at the
  first retry after it comes back, including after this server restarts (ADR-0749).
* The Complement image allows cleartext appservice URLs on `localhost`, where a Complement blueprint registers one;
  the server's own rule and default are unchanged (ADR-0750).
* Tests name their scratch files uniquely and check each write, so a second account or a concurrent run on the
  same machine no longer reads another run's leftover appservice registration and fails (ADR-0753, ADR-0755).
* Unit tests now cover a relation chain that stops short of the thread root (ADR-0746) and a `/send` body that names
  no room (ADR-0756); only the cases that succeed were covered before.
* Two Complement tests whose expectations contradict the spec are expected failures in the skip list: an MXC-only
  `avatar_url` (F-63, ADR-0406) and an omitted `end` at the start of a room (ADR-0470).
* `build.py linux --hardening` and `build.py bsd --hardening` work: both build scripts used to refuse the option they
  were passed (ADR-0752).
* The live-binary startup test runs as a non-root user on the BSDs too: off Linux it accepts the unsandboxed worker,
  as the startup hardening gate does (ADR-0041). It used to fail there.
* `docs/hardening.md` said `federation.worker.apply_hardening=false` alone runs the worker on FreeBSD and OpenBSD;
  it needs `federation.worker.allow_without_landlock=true` too. It now lists the worker's hardening steps in order.
* On a host with an installed system config, the `--dry-run` smoke tests read the example config and the
  default-summary test is skipped, not failed: the server reads that config instead of its defaults (ADR-0752).
* `build.py vm` resends a file an interrupted sync had deleted, and a retry after a sync interrupted inside a new
  directory succeeds, even when the local files changed in between (ADR-0752).
* The VM setup steps in `docs/dev-environment.md` pass the setup key to `scp` and `ssh`, which do not read `vm.ini`.
* A hardened FreeBSD or OpenBSD build links as a PIE however it is built, not only as a package, and the ELF hardening
  check reads the BSDs' `readelf`, so FreeBSD's release evidence no longer reports PIE and BIND_NOW missing (ADR-0757).

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
