Name:           merovingian
Version:        0.10.15
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
BuildRequires:  catch-devel
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
# Create merovingian group if it does not exist
if ! getent group merovingian >/dev/null 2>&1; then
    groupadd -r merovingian
fi
# Create merovingian user if it does not exist
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
# Generate a registration token on first install. Never overwrite an existing token.
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
