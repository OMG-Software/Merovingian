Name:           merovingian
Version:        0.8.9
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
BuildRequires:  libcurl-devel
BuildRequires:  catch-devel
BuildRequires:  perl
BuildRequires:  bison
BuildRequires:  flex
BuildRequires:  m4
BuildRequires:  systemd-rpm-macros

%description
Merovingian is an alpha Matrix Protocol homeserver focused on secure
implementation, runtime hardening, and auditable dependency boundaries.

%prep
%autosetup

%build
%meson \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'
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
%{_unitdir}/merovingian.service
%dir %{_sysconfdir}/merovingian
%{_sysconfdir}/merovingian/merovingian.conf.example

%changelog
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.9-1
- feat: reconstruct auth_chain/auth_chain_ids for federation /state and /state_ids
- test: server-discovery edge-case conformance and PostgreSQL savepoint/concurrency durability
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.8-1
- feat: promote joined_members and single room event retrieval to spec-covered
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.7-1
- fix: collapse pre-production database migrations into complete v1 schema
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.6-1
- feat: server signing-key rotation (rotate_server_signing_key, old_verify_keys publication)
- test: key-rotation conformance, live-Synapse send/signing interop, PostgreSQL durability
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.5-1
- fix: security findings hardening (federation auth, token hashing, EDU parsing, response headers)
* Sat Jun 13 2026 James Chapman <claude@ping.me.uk> - 0.8.4-1
- fix: implement POST /_matrix/client/v3/delete_devices with UIA and idempotent bulk deletion
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.8.3-1
- feat: implement GET/PUT /directory/list/room/{roomId} (room directory visibility)
- feat: implement POST /rooms/{roomId}/upgrade (room upgrade with tombstone)
- feat: promote directory list and upgrade endpoints to spec-covered
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.8.2-1
- feat: add outbound federation delivery conformance fixtures (PUT /send/{txnId} builder, X-Matrix auth, retry/backoff)
- feat: promote outbound delivery and queues from partial to spec-covered
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.8.1-1
- feat: full federation membership conformance coverage (make/send join/leave/knock, invite, backfill)
- fix: make_knock M_INCOMPATIBLE_ROOM_VERSION check (was gated only on make_join)
- fix: send_knock response now includes knock_room_state per Matrix v1.18 spec
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.8.0-1
- feat: promote client-server and federation endpoints from partial to spec-covered
- feat: implement filter_id query parameter on GET /sync
- feat: implement room-version-specific PDU content hash verification on inbound federation
- feat: add Matrix v1.18 conformance fixtures for auth_metadata, thumbnail, sync filter_id, PDU hashing
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.7.2-1
- feat: add GET /query/directory federation conformance with full provider callback
- feat: add make_join M_INCOMPATIBLE_ROOM_VERSION error conformance
- feat: add voip/turnServer authentication conformance test
- feat: promote federation query/directory from partial to spec-covered
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.7.1-1
- feat: add inbound federation transaction idempotency, unknown-EDU, and oversize conformance tests
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.7.0-1
- feat: add conformance fixtures for receipt and user_directory/search endpoints
- feat: add federation key-rotation conformance tests
* Wed Jun 11 2026 James Chapman <claude@ping.me.uk> - 0.6.5-1
- fix: require UIA (m.login.password) for POST /keys/device_signing/upload
* Wed Jun 11 2026 James Chapman <claude@ping.me.uk> - 0.6.2-1
- fix: enforce OTK/fallback key signatures even on first upload (B11)
- fix: strip query strings from rate-limit bucket keys (B12)
- fix: reject invalid JSON events instead of silently converting to m.room.message (B13)
- fix: persist client txnId→event_id mapping to deduplicate room send and to-device retries (B14)
* Wed Jun 11 2026 James Chapman <claude@ping.me.uk> - 0.6.1-1
- fix: add SLSA provenance attestations to rolling package builds (packages.yml)
- fix: attach SPDX and CycloneDX SBOM files to GitHub releases (sbom.yml)
- fix: resolve room version from state in send_join/send_leave/send_knock handlers
- fix: add regression test for OTK Ed25519 signature crypto verification
* Thu Jun 12 2026 James Chapman <claude@ping.me.uk> - 0.6.0-1
- feat: implement POST /publicRooms with filter.generic_search_term, limit, and since pagination
- fix: member visibility â€” startup state repair via repair_missing_state_entries
- fix: pdu_sink tracks remote membership in persistent_store.memberships and LocalRoom.members
- fix: v12 m.room.create room_id derived from event_id in ingest_send_join_state
* Tue Jun 10 2026 James Chapman <claude@ping.me.uk> - 0.5.37-1
- fix(federation): verify relayed PDU signatures against sender domain key, not transport origin
- fix(federation): run authorize_event_against_auth_events before persisting any inbound PDU
* Tue Jun 10 2026 James Chapman <claude@ping.me.uk> - 0.5.36-1
- fix: DELETE /devices/{deviceId} requires UIA re-authentication (spec Â§10.7.1)
- fix: key backup version no longer hardcoded to "1" â€” each POST assigns a unique ID
- fix: PUT /typing validates room existence and membership; EDU uses boolean not string
- fix: POST /read_markers processes m.read and m.read.private alongside m.fully_read
- fix: receipt and read_markers handlers enforce room existence and membership
* Mon Jun 09 2026 James Chapman <claude@ping.me.uk> - 0.5.33-1
- fix: GET /rooms/{roomId}/members returns 403 for non-members (spec Â§11.1)
- fix: POST /account/password requires UIA before changing password (spec Â§5.7)
- fix: registration honours device_id, initial_device_display_name, inhibit_login
- fix: registration UIA token challenge is now conditional on require_token config
- fix: POST /login stores initial_device_display_name on the created device

* Mon Jun 09 2026 James Chapman <claude@ping.me.uk> - 0.5.32-1
- fix(rooms): recover missing membership row from current_state on leave_room
  so a server restart mid-join no longer causes permanent 403 on leave.
  Implement full federated leave (make_leave + send_leave) for rooms hosted
  on remote servers.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.31-1
- Fix cross-server E2EE: include keys field in m.device_list_update EDU so
  remote servers update device caches immediately, eliminating the race window
  that caused OlmError::MissingCiphertext. Fix stream_id hardcoded to 0 in
  GET /user/devices response.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.30-1
- Fix CORS headers missing from non-OPTIONS responses: browsers could not read
  200 sync responses or 4xx error bodies because complete() and sync_json()
  returned DispatchResult without calling apply_cors_headers(). Fixed by
  applying CORS at the single handle_client_server_request public boundary.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.29-1
- Fix reverse-proxy CORS duplicate-header regression: document that proxy-level
  CORS headers must be removed; update nginx example to use $remote_addr instead
  of $proxy_add_x_forwarded_for; add X-Forwarded-For to Apache example.
- Add trusted_proxies guidance to example config and docs; without it all
  clients share one rate-limit bucket behind a reverse proxy.
- Raise default per-IP rate limit from 60/60s to 90/60s.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.28-1
- Fix F5: add remote_addr to LocalHttpRequest; key unauthenticated rate-limit
  buckets by (source-IP, route) instead of a process-global synthetic key;
  honour X-Forwarded-For from configured trusted proxies.
- Fix F7: add SLSA provenance attestations to alpha release workflow via
  actions/attest-build-provenance.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.27-1
- Fix send_join state ingestion: state events with empty state_key (m.room.encryption,
  m.room.create, m.room.power_levels, etc.) are now correctly written to the state table
  when joining a remote room via federation.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.25-1
- Fix F3: accept relayed federation PDUs whose sender domain differs from the
  transaction origin; remove incorrect sender-domain == origin constraint.
- Fix F4: perform real Ed25519 signature verification on uploaded OTK/fallback
  keys instead of a shallow key-ID presence check.
- Fix F6: resolve room version from m.room.create state instead of hardcoding
  "12" in PDU parsing and authorization.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.24-1
- Fix E2EE: broadcast m.device_list_update EDUs to remote servers on key upload
  and room join so remote homeservers (e.g. Synapse) can fetch device keys,
  claim one-time keys, and deliver encrypted room keys to local users.

* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.23-1
- Fix raw access token leaked to audit log on rate-limit denials: resolve
  token to user_id (or "<unknown>") before recording; token bytes never reach
  the audit_log table.
- Fix shallow federation PDU authorization: pdu_is_authorized() was using a
  hardcoded room version "12" and synthetic power level {50,0} rather than
  the actual room auth state. Function renamed to pdu_passes_transport_checks
  to make its scope explicit; full event-auth check wired in at the call site.

* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.22-1
- Fix federated join leaving room invisible to incremental sync: store the
  local join event in store.events with has_state=true so that
  joined_membership_changed_since detects the invite-to-join transition.
  Without this, current_state still pointed at the old invite event and the
  room never surfaced in rooms.join after the client's since-token caught up.

* Sun Jun 08 2026 James Chapman <claude@ping.me.uk> - 0.5.21-1
- Fix Codecov upload for protected branches: add CODECOV_TOKEN support,
  disable redundant gcov search pass, add .codecov.yml project config.
- Fix redaction conformance header: add prev_state to v1-v10 preserved
  top-level fields; correct m.room.join_rules to show join_rule+allow for
  v8-v10; add explicit REQUIRE_FALSE for invite strip in v10 power_levels.
* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.20-1
- Fix stale federated membership: federated invite no longer downgrades an
  existing join membership; join_room retries federation when in-memory
  member state is inconsistent with the persistent membership record.
* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.18-1
- Fix reject-unsafe.sh scanning non-C++ files: restrict grep to C/C++ source
  extensions so Python/JavaScript test files do not trigger false positives.
* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.17-1
- Fix four conformance-test accuracy issues: v1 auth scenarios now use
  v1-valid create fixtures (with room_id); PDU format header documents the
  v12 room_id exception; redaction tests assert membership and add a
  membership/prev_state v10-vs-v11 scenario; sync filter limit==0 sentinel
  is separated into a [helper]-tagged scenario distinct from spec tests.
* Sat Jun 07 2026 James Chapman <claude@ping.me.uk> - 0.5.16-1
- Fix /sync timeline.limited (was derived from the store's total event count, so
  it was true on every sync and made clients endlessly reset the timeline) and
  emit a backfillable timeline.prev_batch; truncated windows now return the most
  recent events

* Fri Jun 06 2026 James Chapman <claude@ping.me.uk> - 0.5.15-1
- Add 7 federation conformance scenarios: query_event, query_state, state_ids,
  get_missing_events, query/profile (with field-filter and 404), make_knock, send_knock

* Fri Jun 06 2026 James Chapman <claude@ping.me.uk> - 0.5.14-1
- Add 12 client-server conformance scenarios: devices, capabilities, joined_rooms,
  publicRooms, directory, register/available, account_data, profile, pushrules, errors

* Fri Jun 06 2026 James Chapman <claude@ping.me.uk> - 0.5.13-1
- Fix m.room.join_rules redaction: allow key now only preserved in v11+
- Fix m.room.aliases redaction: aliases key preserved v1-v10, stripped v11+
- Fix knock authorization: add MembershipState::knock, enforce join_rule check
- Add 21 new conformance scenarios across sync filter, redaction, auth rules, state resolution

* Fri Jun 06 2026 James Chapman <claude@ping.me.uk> - 0.5.11-1
- Split localpart_is_valid into localpart_is_valid_new and localpart_is_valid_federated per spec
- Add user_id_is_valid_federated for historical federation user IDs
- Fix localpart_is_valid_new to reject uppercase (new IDs must be lowercase per spec)

* Fri Jun 06 2026 James Chapman <claude@ping.me.uk> - 0.5.10-1
- Fix v12 m.room.create PDU: allow absent room_id, derive it from reference hash
- Enforce v12 auth_events exclusion of create event at inbound parse time
- Fix GET /sync returning no 400 for malformed inline filter JSON (M_BAD_JSON)
- Fix canonical JSON parser rejecting -0 per spec
- Fix missing default push rules: .m.rule.contains_display_name and .m.rule.roomnotif
- Fix state resolution regression from Codex changes

* Fri Jun 05 2026 James Chapman <claude@ping.me.uk> - 0.5.9-1
- Bind client key APIs and /account/whoami to the authenticated session device
  instead of a guessed first device, fixing registration-issued tokens and
  multi-device E2EE bootstrap.
- Add strict regressions proving registration and multi-device sessions can
  upload device keys for the correct authenticated device.
* Fri Jun 05 2026 James Chapman <claude@ping.me.uk> - 0.5.8-1
- Fix local Matrix room and E2EE interop by normalizing device key bundles,
  surfacing joined-room ephemerals in /sync, and returning client-formatted
  membership state from /members.
- Add strict regressions and an end-to-end client-shaped flow covering login,
  invite/join, keys/query, keys/claim, sendToDevice, encrypted messaging,
  read receipts, and leave.
* Fri Jun 05 2026 James Chapman <claude@ping.me.uk> - 0.5.7-1
- Percent-decode the client account-data type path segment before persistence
  and lookup, so secret-storage descriptors like m.secret_storage.key.<id>
  round-trip correctly through PUT/GET and /sync account_data.events.
- Add strict regressions covering percent-encoded secret-storage account-data
  types in both the runtime and conformance suites.

* Thu Jun 05 2026 James Chapman <claude@ping.me.uk> - 0.5.6-1
- Report device_one_time_keys_count.signed_curve25519 = 0 for fresh devices so
  Matrix clients know they must upload one-time keys during E2EE bootstrap.
- Add strict client-shaped coverage for local PUT /sendToDevice/m.room.encrypted
  delivery into /sync to_device.events.

* Wed Jun 04 2026 James Chapman <claude@ping.me.uk> - 0.5.5-1
- Fix GET /rooms/{roomId}/messages to return client-format events with event_id
  in both timeline chunk and state arrays, so Matrix clients can parse and
  decrypt encrypted room history correctly.
- Handle browser OPTIONS preflight before client-server rate limiting so
  repeated cross-origin checks no longer consume the real route bucket or
  trigger 429 M_LIMIT_EXCEEDED on the subsequent request.
- Add strict regressions covering both interop failures: /messages event_id
  serialization and preflight bucket bypass.

* Wed Jun 04 2026 James Chapman <claude@ping.me.uk> - 0.5.4-1
- Fix encrypted invite-accept E2EE bootstrap for local clients.
- Add strict conformance coverage for local keys/changes, keys/query, keys/claim,
  sendToDevice targeting/draining, and post-join room-key delivery.

* Wed Jun 04 2026 James Chapman <claude@ping.me.uk> - 0.5.3-1
- Persist local invite metadata for same-server invitees so /sync invites include invite_state.events
- Allow POST /rooms/{roomId}/leave to reject invites as well as leave joined rooms
- Persist leave membership state events on local leaves and clear stale invite metadata on join/leave/ban
- Replace placeholder membership gap tests with strict Matrix v1.18 conformance coverage for invite, ban, kick, unban, forget, and knock

* Wed Jun 03 2026 James Chapman <claude@ping.me.uk> - 0.5.2-1
- Fix local invite-to-join membership transitions: invited local users no longer count as joined before a join event exists
- Local joins now persist a fresh m.room.member state event with content.membership=join, so /rooms/{roomId}/members and /sync stop surfacing stale invite state after accept
- Runtime hydration now rebuilds LocalRoom.members from join memberships only, preventing the stale invite bug from reappearing after restart

* Wed Jun 03 2026 James Chapman <claude@ping.me.uk> - 0.5.1-1
- Wire the wall-clock rate-limit engine, per-module log-level overrides, and audit-routing helper into production
- New client_rate_limits.* config keys (per-IP and per-user, keyed by target prefix, format <N>/<Ws>s) replace the legacy request-counter window
- New log_modules.* config keys for per-module and wildcard default log levels (restart required)
- /_merovingian/admin/audit accepts ?category= and ?event_type= query-string filters; unknown categories return 400
- Five high-signal failure call sites now route through observability::log_diagnostic_audit, which at severity warning or above appends a row to audit_log with the same actor / target / reason as the structured log line: rate_limit.exceeded, login.rejected, access_token.rejected, request.rejected, registration_policy.denied
- New operator docs: docs/log-filtering.md

* Tue Jun 02 2026 James Chapman <claude@ping.me.uk> - 0.4.62-1
- /keys/upload now validates that one-time and fallback keys are signed by the device's own ed25519 identity key, rejecting unverifiable keys with 400 M_INVALID_SIGNATURE. Fixes the Element "No key bundle found for user" / "NoSignatureFound" bug seen on pong.ping.me.uk where a stale device row left behind OTKs that no peer could verify.

* Tue Jun 02 2026 James Chapman <claude@ping.me.uk> - 0.4.61-1
- Merovingian now emits Access-Control-* response headers itself, so a vanilla reverse proxy that does not synthesize CORS headers stops breaking browser clients (Element, etc.) on every cross-origin request
- New server.cors.* config keys: allowed_origins, max_age, allow_credentials, allow_methods, allow_headers
- Reject server.cors.allow_credentials=true combined with a wildcard origin (CORS spec violation)
- Reverse-proxy deployment guide expanded with copy-pasteable configs for nginx, Apache, Caddy, Traefik, HAProxy, and Cloudflare

- Canonical-JSON integer parsing now rejects leading zeros and explicit positive signs per Matrix spec
- yyjson adapter passes YYJSON_READ_STOP_WHEN_DONE to reject trailing-garbage payloads
- HTTP read_request_head gains a 30 s overall deadline plus a 5 s inter-byte cap to defeat slowloris
- Thread-pool and http-server swallowed-exception sites now log the type and what() of the caught exception
- schema_migrations INSERT switched from string concatenation to a PreparedStatement
- thread_pool::request_stop and sqlite_transient_destructor non-reentrancy / lifetime contracts are now documented and debug-asserted

* Sun Jun 01 2026 James Chapman <claude@ping.me.uk> - 0.4.58-1
- Fix registration UIAuth: incomplete auth credentials (missing token or wrong auth.type) now return 401 UIA challenge instead of 403

* Sun Jun 01 2026 James Chapman <claude@ping.me.uk> - 0.4.57-1
- Tighten Matrix v1.18 /sync conformance: assert full envelope shape including rooms.knock
- Implement registration discovery routes (register/available, registration_token/validity, email/requestToken, msisdn/requestToken)
- Fix register UIA probing for empty JSON bodies to return 401 challenge instead of 400 M_BAD_JSON
- Fix push-rule discovery for authenticated clients (server-default ruleset, global, actions/enabled views)
- Fix stable unauthenticated OIDC discovery probing (auth_metadata returns 404 M_UNRECOGNIZED)
- Fix outbound federation transaction IDs for E2EE to-device delivery
- Fix federated profile query for local users missing stored profile row
- Fix inbound m.direct_to_device EDU parsing for encrypted payloads
- Tighten register error conformance (M_INVALID_USERNAME for invalid localparts)
