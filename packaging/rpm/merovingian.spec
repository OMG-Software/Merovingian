Name:           merovingian
Version:        0.2.3
Release:        1%{?dist}
Summary:        A secure Matrix Protocol homeserver

License:        GPL-3.0-or-later
URL:            https://github.com/merovingian-homeserver/merovingian
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
Merovingian is an alpha Matrix Protocol homeserver.
Secure by design, implementation, and during runtime.

%prep
%autosetup

%build
%meson \
    --wrap-mode=forcefallback \
    --prefer-static \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'
%meson_build

%install
%meson_install
install -D -m 0644 packaging/systemd/merovingian.service \
    %{buildroot}%{_unitdir}/merovingian.service
install -d -m 0755 %{buildroot}%{_sysconfdir}/merovingian

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

%preun
%systemd_preun merovingian.service

%postun
%systemd_postun_with_restart merovingian.service

%files
%license LICENSE
%doc README.md
%{_bindir}/merovingian-server
%{_bindir}/merovingian-db-migrate
%{_unitdir}/merovingian.service
%dir %{_sysconfdir}/merovingian

%changelog
* Tue May 19 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.3-1
- 0.2.3: restore -fPIE and -Wl,-z,noexecstack; PIE now supplied per-platform via -pie

* Tue May 19 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.2-1
- 0.2.2: statically link application deps; remove shared-lib Requires; add --prefer-static

* Tue May 19 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.1-1
- Bump to 0.2.1: add systemd scriptlets, %pre user creation, service file install
