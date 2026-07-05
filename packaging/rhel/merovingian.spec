Name:           merovingian
Version:        0.10.28
Release:        1%{?dist}
Summary:        Secure Matrix Protocol homeserver

License:        GPL-3.0-or-later
URL:            https://github.com/OMG-Software/Merovingian
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  git
BuildRequires:  openssl-devel
BuildRequires:  libsodium-devel
BuildRequires:  libpq-devel
BuildRequires:  libpng-devel
BuildRequires:  turbojpeg-devel
BuildRequires:  libcurl-devel
BuildRequires:  perl
BuildRequires:  bison
BuildRequires:  flex
BuildRequires:  m4
BuildRequires:  systemd-rpm-macros

Requires:       openssl-libs
Requires:       libsodium
Requires:       libpq
Requires:       libcurl
Requires:       libpng
Requires:       libjpeg-turbo

%description
Merovingian is a beta Matrix Protocol homeserver focused on secure
implementation, runtime hardening, and auditable dependency boundaries.

%prep
%autosetup

%build
%meson \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie -Wl,-z,relro -Wl,-z,now' \
    -Dc_link_args='-pie -Wl,-z,relro -Wl,-z,now'
%meson_build

%install
%meson_install --skip-subprojects
install -D -m 0644 packaging/systemd/merovingian.service \
    %{buildroot}%{_unitdir}/merovingian.service
install -d -m 0755 %{buildroot}%{_sysconfdir}/merovingian
install -m 0644 config/merovingian.conf.example \
    %{buildroot}%{_sysconfdir}/merovingian/merovingian.conf.example

%pre
if ! getent group merovingian >/dev/null 2>&1; then
    groupadd -r merovingian
fi
if ! getent passwd merovingian >/dev/null 2>&1; then
    useradd -r -g merovingian -d /var/lib/merovingian \
            -s /sbin/nologin \
            -c "Merovingian homeserver" \
            merovingian
fi

%post
%systemd_post merovingian.service
install -d -o merovingian -g merovingian -m 0750 /var/lib/merovingian
install -d -o merovingian -g merovingian -m 0750 /var/log/merovingian
TOKEN_FILE=%{_sysconfdir}/merovingian/registration-token
if [ ! -f "${TOKEN_FILE}" ]; then
    openssl rand -base64 48 > "${TOKEN_FILE}"
    chmod 0640 "${TOKEN_FILE}"
    chown root:merovingian "${TOKEN_FILE}"
fi

%preun
%systemd_preun merovingian.service

%postun
%systemd_postun_with_restart merovingian.service

%files
%license LICENSE
%doc README.md docs/configuration.md docs/release-process.md
%{_bindir}/merovingian-server
%{_bindir}/merovingian-db-migrate
%dir %{_libexecdir}/merovingian
%{_libexecdir}/merovingian/merovingian-thumbnail-worker
%{_libexecdir}/merovingian/merovingian-fed-worker
%{_unitdir}/merovingian.service
%dir %{_sysconfdir}/merovingian
%{_sysconfdir}/merovingian/merovingian.conf.example

%changelog
* Sun Jul 05 2026 James Chapman <claude@ping.me.uk> - 0.10.28-1
- fix(federation,e2ee): broadcast local device-list updates to remote joiners and keep EDU-only /send transactions in main after X-Matrix verification
* Sun Jul 05 2026 James Chapman <claude@ping.me.uk> - 0.10.26-1
- fix(federation-worker): a federation worker shard could go fully unresponsive for ~30s at a time with no crash logged, because a single fixed-size thread pool handled both new incoming requests and synchronous IPC callbacks back to main; a burst of the latter could occupy every thread and starve the former. Splits into a local_pool (endpoints answered from the worker's own snapshot) and a new relay_pool (federation.worker.relay_threads, default 32, for endpoints that can block on main or on outbound HTTP)
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.25-1
- diag(federation): WorkerPool::handle() now logs the status, body length, and a short body prefix of every reply a federation worker sends back, to determine whether handle_inbound_federation_request's own logging has a real gap or the reply is coming from somewhere else entirely
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.24-1
- fix(federation,security): the federation worker's user_devices_provider, device_keys_query_provider, and profile_query_provider decided their answers from a per-process in-memory snapshot hydrated once at worker startup with no refresh mechanism, so a remote server querying a real local user's devices to share an E2EE room key could get a spurious 404 forever; all three are now relayed to main over IPC the same way one_time_keys_claim_provider is
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.23-1
- fix(media,security): remote-fetched media fabricated a scanner-clean/decoder-safe verdict for federated content; the remote fetch now reports scanner_clean=false honestly, and a new MediaAcceptancePolicy (allow/allow-after-scan/quarantine/deny) is configurable independently for local uploads and remote fetches (security.media.local_upload_policy, security.media.remote_fetch_media_policy), defaulting remote-fetched media to quarantine
- fix(media,security): the outbound federation media download URL omitted the {serverName} path segment required by the spec and neither segment was percent-encoded; both are now included and encoded via remote_media_download_url()
- fix(http,security): trusted-proxy X-Forwarded-For rate-limit keying accepted any non-empty value verbatim with no IP validation, letting spoofed pseudo-IP values defeat per-IP rate limiting; the candidate is now validated as a real IPv4/IPv6 literal and falls back to the direct peer address otherwise
- fix(media,security): admin media quarantine/release/remove routes accepted unsanitized media IDs from the raw path suffix, treating a trailing query string or path-traversal sequence as part of the media ID; admin_media_id_from_suffix() now strips query strings and rejects unsafe IDs before the admin action runs
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.22-1
- test(federation): add failure-path integration coverage for the 0.10.19-0.10.21 worker/main relay fixes — membership_ingest (room not found, acceptor unwired), edu_ingest (malformed content, sink unwired), invite_ingest (unknown local invitee, handler unwired), and otk_claim_ingest (double-claim consumption, no key available) — closing gaps where only the accepted/happy path was previously tested
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.21-1
- fix(federation): federation worker's invite_handler persisted a federated invite's membership row, invite metadata, and event only into the worker's own local store, never relaying it to main — the same class of bug 0.10.19 fixed for membership_acceptor. A remote server inviting a local user to a room hosted elsewhere was silently swallowed with no trace anywhere. invite_handler now relays through main via a new invite_ingest IPC call
- fix(federation,security): federation worker's one_time_keys_claim_provider decided key availability from a per-process in-memory snapshot taken once at worker startup, risking a one-time prekey being handed out twice (breaking Olm's single-use guarantee) if a worker ever fell back to main, and going permanently stale once its startup snapshot was exhausted even as fresh keys were uploaded through main. one_time_keys_claim_provider now relays through main via a new otk_claim_ingest IPC call so every claim is decided against the single authoritative store
- fix(federation): ordinary messages and state changes never refreshed a federation worker's room snapshot — only the 7 membership-mutating calls did — so worker-served backfill/event/state/state_ids/get_missing_events queries could silently omit recent history in active rooms. send_event and the main-side pdu_ingest relay handler now also call notify_room_changed
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.20-1
- fix(federation): federation worker's edu_sink was a hard no-op, silently dropping every inbound EDU it handled — including m.direct_to_device, the transport for E2EE megolm room-key shares — while still counting them as "dispatched" in logs; recipients whose key-share transaction landed on a worker shard were left permanently unable to decrypt affected messages with no trace of the failure anywhere in the server logs. edu_sink now relays through main via a new edu_ingest IPC call, the same way pdu_sink and membership_acceptor already do
* Sat Jul 04 2026 James Chapman <claude@ping.me.uk> - 0.10.19-1
- fix(federation): a federated join/leave/knock accepted by a federation worker was never visible to the main process's own room state; every subsequent message from that member was rejected with "sender is not joined to the room" — membership_acceptor now relays through main via a new membership_ingest IPC call, the same way pdu_sink already does
* Fri Jul 03 2026 James Chapman <claude@ping.me.uk> - 0.10.18-1
- fix(federation): worker shard routing hashed the raw percent-encoded room ID from room-scoped federation paths (e.g. make_join's "%21room:example.com"), which never matches the plain-text room_id used by notify_room_changed()/room_service; with more than one federation.worker.shards configured this routed the request to a shard that was never synced for the room, so every room-scoped federation request 404'd even though the room existed locally
* Fri Jul 03 2026 James Chapman <claude@ping.me.uk> - 0.10.17-1
- fix(sync): rooms.leave.<room_id>.timeline in the /sync response was always an empty events array, so a real client never actually saw itself leave even though the server correctly advanced stream_ordering and notified sync; the timeline now includes the user's m.room.member leave event, which real clients (matrix-js-sdk) require to update their own membership state
* Fri Jul 03 2026 James Chapman <claude@ping.me.uk> - 0.10.16-1
- fix(sync,federation): leave_room's repeat-leave idempotent path now refreshes stream_ordering and re-notifies sync/federation on every call, not just the first; previously a client whose earlier leave was stuck under the pre-0.10.15 bug would retry /leave forever without ever healing, because the idempotent no-op path skipped the stream_ordering refresh entirely
* Fri Jul 03 2026 James Chapman <claude@ping.me.uk> - 0.10.15-1
- fix(database): update_membership() now persists stream_ordering on every membership transition (join->leave, invite, kick, ban, rejoin), not just on first insert; previously an existing row's stream_ordering stayed frozen at its original insert value forever, so any since-token comparison against it could never see a later transition as recent
- fix(sync): report a room in the /sync `leave` block whenever the caller's own membership changed to leave/ban/kick since the `since` token, regardless of the `include_leave` filter; previously any leave/kick/ban was silently omitted from incremental sync unless the client opted in with `include_leave: true` (which most clients never set), so `/leave` returned 200 but the room never disappeared from the client's room list
- fix(federation): invite_user/ban_user/kick_user/unban_user now notify the federation worker via room_sync, closing a gap in the 0.10.14 staleness fix that only covered create_room/join_room/leave_room; previously inviting a remote user to an existing, already-resident room could leave the worker permanently unaware of the room, causing the remote server's make_join to 404 indefinitely
* Thu Jul 02 2026 James Chapman <claude@ping.me.uk> - 0.10.14-1
- fix(federation): add security.federation.join_response_max_size (default 64MiB) so send_join for a huge room is no longer rejected with 502 "response_too_large" once it fits within the join timeout budget; the federation-worker IPC frame cap now scales with this value via ipc::frame_bytes_for_response_cap (restart required)
- fix(federation): notify the federation worker via a new room_sync IPC message when create_room/join_room/leave_room change this server's residency, and add database::reload_room() so the worker refreshes its otherwise permanently-stale per-room PersistentStore snapshot instead of 404ing inbound make_join/state for rooms created or joined after its own startup
- fix(database): add database::reconstruct_event_relations() so PersistentEvent prev_event_ids/auth_event_ids/signatures are populated from the event_edges/event_auth/event_signatures tables on every store hydration, not silently left empty after a restart
* Thu Jul 02 2026 James Chapman <claude@ping.me.uk> - 0.10.13-1
- fix(federation): send_join used remote_timeout_seconds instead of the join_timeout_seconds budget, causing large-room joins to fail with 502 "IPC timeout waiting for outbound HTTP result"; also guard perform_sync_outbound_call against timeout_seconds=0 collapsing the IPC window to 10s
- fix(config): add the missing security.federation.join_timeout/join_parallelism/join_race_deadline/join_max_candidates/join_state_key_parallelism and federation.worker.apply_hardening keys to config/merovingian.conf.example
* Thu Jul 02 2026 James Chapman <claude@ping.me.uk> - 0.10.12-1
- test(federation): add a live join_room integration test covering the fast-join/signature-verification code path against a real local TLS server, closing the codecov/patch gap from #341; adds a test-only outbound destination override to HomeserverRuntime (never set by production code) so tests can point federation calls at a local server without weakening the SSRF/loopback policy or the TLS CA trust store
* Wed Jul 01 2026 James Chapman <claude@ping.me.uk> - 0.10.11-1
- feat(federation): fast join - verify and persist critical room state (create/power_levels/join_rules/our own membership) synchronously, defer the bulk membership list to a background task tracked in orphan_futures_, so a large room's join response no longer waits on resolving every member's home server key
- fix(security): verify send_join state/auth_chain event signatures with bounded-parallel remote key resolution (security.federation.join_state_key_parallelism, default 100) instead of trusting the resident server's response wholesale
- fix(federation): advertise all server-supported room versions (v1-v12) in outbound make_join and GET /capabilities instead of a hardcoded v10-v12, which made federation joins to any older-versioned room fail with 400 M_INCOMPATIBLE_ROOM_VERSION against every real resident server
- fix(federation): bound the make_join race with a configurable overall deadline and cap the number of via candidates actually raced, so a join against a large well-federated room returns a definitive response before the client's own fetch times out
* Mon Jun 30 2026 James Chapman <claude@ping.me.uk> - 0.10.10-1
- fix(federation): parallel make_join across candidate servers, configurable join timeout, TTL discovery cache, parallel inbound key resolution for faster remote room joins
* Mon Jun 30 2026 James Chapman <claude@ping.me.uk> - 0.10.9-1
- fix(security): harden federation-worker IPC boundary and key separation - authenticate crypto_kx handshake with master-key MAC (#318); replace hand-rolled IPC JSON parser with fuzzed canonicaljson (#320); noexcept allocation-failure safety in IpcChannel (#324); lower IPC frame cap to 16 MiB and surface oversize drops (#325); minimal worker environment via posix_spawn (#330); worker-specific seccomp + runtime hardening (#319); derive legacy v3 access-token HMAC key from master key, not the Ed25519 seed (#322, breaking - re-login required); handle escaped quotes in X-Matrix Authorization parser (#321); keep server signing secret in SecretBuffer/span, not std::string (#317); main verifies inbound X-Matrix signature and forwards only the verified peer identity to the worker - raw peer credentials never cross IPC (#323)
* Mon Jun 29 2026 James Chapman <claude@ping.me.uk> - 0.10.8-1
- fix(platform): add numeric fallbacks for rseq/membarrier/getcpu/futex_waitv in seccomp filter to prevent SIGSYS on glibc 2.35+ when built with older kernel headers

* Mon Jun 29 2026 James Chapman <claude@ping.me.uk> - 0.10.7-1
- feat(platform): implement OpenBSD pledge/unveil and FreeBSD Capsicum capability mode hardening with CI tests

* Sun Jun 28 2026 James Chapman <claude@ping.me.uk> - 0.10.6-1
- feat(federation): route join/leave outbound calls through federation worker; discovery timeout now honours configured remote_timeout; example config remote_timeout corrected to 60s; deleted-file guard and worktree-safe hook installer

* Sun Jun 28 2026 James Chapman <claude@ping.me.uk> - 0.10.4-1
- feat(federation): make federation worker mandatory; remove enabled/fallback_in_process config; fix TOCTOU channel race, PDU room_id routing for nested JSON, spurious sync wakeup, and zero threads/timeout validation

* Sat Jun 27 2026 James Chapman <claude@ping.me.uk> - 0.10.3-1
- feat(federation): room-sharded federation workers (Phase 3); inbound requests are routed by room ID across N independent merovingian-fed-worker processes using FNV-1a hashing

* Sat Jun 27 2026 James Chapman <claude@ping.me.uk> - 0.10.2-1
- feat(federation): sign-back channel for federation worker (Phase 2); worker delegates Ed25519 signing to main process via IPC so the signing secret never enters the worker

* Sat Jun 27 2026 James Chapman <claude@ping.me.uk> - 0.10.1-1
- feat(federation): introduce merovingian-fed-worker out-of-process federation worker with encrypted IPC channel to isolate federation CPU/IO from client-server threads

* Thu Jun 25 2026 James Chapman <claude@ping.me.uk> - 0.9.23-1
- fix(client-server): implement POST /_matrix/client/v3/pushers/set so Element X can register push notifications without route-not-found errors

* Wed Jun 24 2026 James Chapman <claude@ping.me.uk> - 0.9.21-1
- fix(sync): emit explicit m.typing stop events so typing notifications can restart after a user stops typing

* Tue Jun 23 2026 James Chapman <claude@ping.me.uk> - 0.9.20-1
- fix(database): persist sync_stream_watermark so sync stream IDs cannot roll back across restart
- fix(sync): ensure ephemeral typing and receipt events advance the persistent sync stream counter
- fix(sync): deliver typing notifications to /sync recipients after homeserver restart
- test(database): add regression coverage for sync stream watermark persistence
- test(sync): add typing notification delivery regression test

* Tue Jun 23 2026 James Chapman <claude@ping.me.uk> - 0.9.19-1
- fix(sync): stop ElementX sliding-sync loop caused by repeated room re-inclusion
- fix(sync): wake MSC4186 sliding sync long-poll on typing and read receipts in joined rooms

* Mon Jun 22 2026 James Chapman <claude@ping.me.uk> - 0.9.18-1
- feat(client-server): implement room tag endpoints and general JSON double support

* Mon Jun 22 2026 James Chapman <claude@ping.me.uk> - 0.9.17-1
- feat(homeserver): implement Matrix space hierarchy endpoints

* Sun Jun 22 2026 James Chapman <claude@ping.me.uk> - 0.9.16-1
- fix(media): media download and thumbnail endpoints no longer 404 on query parameters and now return raw bytes with Content-Type

* Sun Jun 21 2026 James Chapman <claude@ping.me.uk> - 0.9.14-1
- test(database): add more direct persistence-helper coverage

* Sun Jun 21 2026 James Chapman <claude@ping.me.uk> - 0.9.10-1
- fix(sync): MSC4186 sliding sync long-poll no longer returns early when only another user's device keys were uploaded
- test(sync): add BDD test verifying sliding sync spurious-wakeup suppression

* Sun Jun 21 2026 James Chapman <claude@ping.me.uk> - 0.9.9-1
- fix(sync): incremental MSC4186 sliding sync no longer returns unchanged rooms, ending the Element X tight-poll loop
- test(sync): add BDD unit tests for build_room_response incremental required_state filtering

* Sun Jun 21 2026 James Chapman <claude@ping.me.uk> - 0.9.8-1
- test(client-server): add joined_members and presence route coverage for current-member gates, profile shaping, defaults, and sync delivery

* Sun Jun 21 2026 James Chapman <claude@ping.me.uk> - 0.9.7-1
- fix(sync): route POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync to the MSC4186 handler for matrix-rust-sdk (Element X) compatibility

* Sat Jun 20 2026 James Chapman <claude@ping.me.uk> - 0.9.6-1
- fix coverage reporting to exclude src/main.cpp and count only Merovingian public headers
- add tooling guards and sliding sync unit coverage for room-list and extension paths

* Fri Jun 20 2026 James Chapman <claude@ping.me.uk> - 0.9.5-1
- fix(rooms): GET/POST publicRooms?server= now proxies to remote homeserver via federation
* Sat Jun 20 2026 James Chapman <claude@ping.me.uk> - 0.9.4-1
- feat(sync): add MSC4186 Simplified Sliding Sync (POST /_matrix/client/unstable/org.matrix.msc4186/sync)
* Sat Jun 20 2026 James Chapman <claude@ping.me.uk> - 0.9.3-1
- fix(sync): server now respects client-requested timeout; defaults to 20 s when omitted
- fix(log): promote major auth and server lifecycle events from DEBUG to INFO

* Fri Jun 20 2026 James Chapman <claude@ping.me.uk> - 0.9.2-1
- fix(auth): access tokens no longer silently expire for clients that did not opt into refresh tokens

* Fri Jun 19 2026 James Chapman <claude@ping.me.uk> - 0.9.1-1
- Beta milestone: promote from pre-beta (0.8.x) to beta phase.
