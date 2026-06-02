Name:           merovingian
Version:        0.4.59
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
* Tue Jun 02 2026 James Chapman <claude@ping.me.uk> - 0.4.59-1
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