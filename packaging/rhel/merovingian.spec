Name:           merovingian
Version:        0.8.18
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
%{_unitdir}/merovingian.service
%dir %{_sysconfdir}/merovingian
%{_sysconfdir}/merovingian/merovingian.conf.example

%changelog
* Wed Jun 17 2026 James Chapman <claude@ping.me.uk> - 0.8.18-1
- Security hardening: seccomp fail-closed, thumbnail worker fd sandbox, state caps, token key separation, atomic migrations.

* Mon Jun 16 2026 James Chapman <claude@ping.me.uk> - 0.8.18-1
- fix(crypto): encrypt the Ed25519 server signing secret at rest when a master key is configured
- fix(auth): hash the registration token with Argon2id instead of storing/comparing plaintext
- fix(ci): harden OpenSUSE Tumbleweed dependency install against transient zypper refresh timeouts

* Mon Jun 16 2026 James Chapman <claude@ping.me.uk> - 0.8.16-1
- fix: pin federation auth destination server-side in the local router to close a relay/replay vector
- fix: back constant_time_equal with libsodium sodium_memcmp; auth delegates to the crypto wrapper
* Mon Jun 16 2026 James Chapman <claude@ping.me.uk> - 0.8.15-1
- fix: guard curl write callback against unsigned underflow when body exceeds cap
- fix: guard thumbnailer framing against size_t-to-uint32_t silent truncation for large payloads
- fix: use saturating multiply for thumbnail worker memory limit to prevent uint64_t overflow
* Mon Jun 16 2026 James Chapman <claude@ping.me.uk> - 0.8.14-1
- feat: add fuzz targets for sync filter, config parser, stream token, query params, and SRV record parsing
* Mon Jun 15 2026 James Chapman <claude@ping.me.uk> - 0.8.12-1
- Initial OpenSUSE Tumbleweed package
- ci: add Debian trixie, RHEL-compatible, and OpenSUSE Tumbleweed CI and packaging jobs
