Name:           merovingian
Version:        0.5.8
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
* Fri Jun 05 2026 James Chapman <claude@ping.me.uk> - 0.5.8-1
- Fix local Matrix room and E2EE interop by normalizing device key bundles,
  surfacing joined-room ephemerals in /sync, and returning client-formatted
  membership state from /members.
- Add strict regressions and an end-to-end client-shaped flow covering login,
  invite/join, keys/query, keys/claim, sendToDevice, encrypted messaging,
  read receipts, and leave.

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
