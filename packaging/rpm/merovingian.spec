Name:           merovingian
Version:        0.2.10
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
