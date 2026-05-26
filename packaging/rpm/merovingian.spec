Name:           merovingian
Version:        0.4.12
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
* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.12-1
- Bump project and packaging metadata to 0.4.12 for a fresh main latest build

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.11-1
- Log the merovingian-server version during startup

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.10-1
- Persist inbound federation join membership for remote event delivery
- Sign and persist inbound federation invites for client sync
- Send outbound federation invites for remote createRoom invitees

* Sun May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.9-1
- Add live Synapse federation integration tests against matrix.ping.me.uk

* Sun May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.8-1
- Fix runtime_lock held during /sync long-poll blocking federation dispatch

* Sun May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.6-1
- Fix federation transaction response to return spec-required JSON {"pdus":{}}

* Sun May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.5-1
- Add v1.18 conformance fixtures for client-server and federation
- Fix DispatchWorker overwrite and empty transaction_id bugs

* Sat May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.4-1
- Wire inbound EDU sink for all five EDU types (typing, receipt, presence, to-device, device_list_update)
- Wire outbound membership into join_room for remote rooms (make_join → sign → send_join)
- Wire device list update route and record_device_list_change
- Add outbound EDU dispatch for typing notifications and read receipts
- Add PUT /presence/{userId}/status route

* Sat May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.3-1
- Fix inbound PDU sync visibility (stream_ordering and sync notification for federation events)
- Wire outbound PDU dispatch from local events to remote servers via DispatchWorker

* Sat May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.2-1
- Fix federation invite path parsing (v1/v2 invite routes no longer emit spurious membership_path.rejected)
- Add im.nheko.summary room summary endpoints for Nheko compatibility

* Fri May 23 2026 James Chapman <claude@ping.me.uk> - 0.4.1-1
- Fix room join returning 500 when user is already a member in the persistent store but absent from the in-memory member list

* Fri May 23 2026 James Chapman <claude@ping.me.uk> - 0.4.0-1
- Add POST /rooms/{roomId}/leave and /read_markers client-server routes
- Add structured debug logging to federation, media, platform, and HTTP modules
- Fix platform library linkage in merovingian-db-migrate

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.6-1
- Add client-server room messages and typing routes

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.5-1
- Add inbound federation event-graph routes: event/{eventId}, state/{roomId}, state_ids/{roomId}, and get_missing_events/{roomId}

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.4-1
- Add inbound federation query/profile route
- Add inbound federation E2EE key routes: user/keys/query, user/keys/claim, and user/devices

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.3-1
- Complete federation joins/leaves/invites/backfill/PDU delivery/event ingestion
- Add real X-Matrix header parsing and TLS-bound origin validation
- Wire remote key rotation with live Ed25519 fetch and cache
- Wire all FederationRuntimeState callbacks into the production runtime
- Extend PostgreSQL restart-survival tests to cover all persisted data types

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.2-1
- HTML character encoding fix

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.1-1
- Add redaction-aware debug diagnostics across HTTP dispatch, client-server auth, joins, room events, persistence, and federation membership flows

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.0-1
- Add Matrix UI-auth challenge for POST /register (returns 401 with flows/session when auth field absent)
- Add POST /account/password endpoint for authenticated password change
- Add PUT /profile/{userId}/displayname and avatar_url endpoints
- Move GET /profile/{userId} before the auth gate (unauthenticated per Matrix spec)
- Fix GET /profile/{userId}/{keyName} to return only the requested field (404 for unset/unknown fields)
- Extend client-server v1.18 conformance fixture with profile negative cases, unknown-room state, and password-change coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.17-1
- Add durable media blob persistence, policy-rule hydration, and hardened media processing boundaries
- Add remote media ingest boundary, thumbnail metadata, and media repository restart coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.16-1
- Promote beta client-server v1.18 endpoint coverage with auth/device runtime behavior and conformance fixtures
- Add refresh-token rotation, global logout, single-device fetch/delete, spec-shaped room send/state aliases, and media adapter coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.15-1
- Return 404 for the whole org.matrix.msc2965 OIDC discovery namespace
- Add GET /voip/turnServer stub returning an empty object
- Add POST /join/{roomIdOrAlias} join-by-id endpoint
- Add PUT/GET /user/{userId}/account_data/{type} for global account data

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.14-1
- Raise the client API body limit to 64 KiB so E2EE key uploads are not rejected with 413
- Add GET /profile/{userId} and GET /_matrix/media/v3/config stubs
- Return 404 for the org.matrix.msc2965 OIDC auth_metadata probe

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.13-1
- Fix the Windows-to-WSL build launch chain to use scripts/build-wsl.sh
- Re-extract stale curl packagefiles and normalize the staged WSL make shim

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.12-1
- Add POST /user/{userId}/filter and GET /user/{userId}/filter/{filterId} so Cinny can store and retrieve sync filters

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.11-1
- Add GET /capabilities and GET /pushrules/ stubs so Cinny and Element can complete post-login initialisation

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.10-1
- Add OPTIONS preflight handler and /.well-known/matrix/client endpoint

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.9-1
- Fix login returning HTTP 400 instead of 403 for unknown user and bad credentials

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.8-1
- Fix malformed INSERT SQL in login and register boundary plans

* Tue May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.7-1
- Bump version to 0.2.7

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.6-1
- Generate /etc/merovingian/registration-token on first install
- Default config search path baked in via MEROVINGIAN_SYSCONFDIR at build time

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.5-1
- Move the default internal federation listener away from public port 8448

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.4-1
- Add explanatory comments to the example configuration

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.3-1
- Add static Linux fallback tarball to rolling package publication
- Fix rolling latest release replacement

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.2-1
- Switch .deb build to Ubuntu with dynamic security library linking
- Declare libssl3, libsodium23, libpq5 as runtime deps in .deb package

* Tue May 19 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.1-1
- Add distro packaging: .deb, .rpm, FreeBSD .pkg via CI
- Statically link application deps; remove shared-lib Requires
- Restore -fPIE and -Wl,-z,noexecstack; PIE supplied per-platform via cpp_link_args
