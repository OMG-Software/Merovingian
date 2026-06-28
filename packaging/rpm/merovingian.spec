Name:           merovingian
Version:        0.10.5
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
