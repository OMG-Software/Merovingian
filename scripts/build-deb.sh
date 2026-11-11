#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build for merovingian 0.12.93.
set -e

VERSION="0.12.93"
PKG_NAME="merovingian"
STAGING="staging-deb"

# 1. Configure with meson.
#    --wrap-mode=forcefallback: vendored deps (SQLite, yyjson) are built from
#    source-pinned wraps; OS-supplied libraries (OpenSSL, libsodium, libpq,
#    libcurl) are resolved from the system with allow_fallback=false.
#    -pie: position-independent executable so the kernel applies ASLR.
#    --buildtype=release: Meson otherwise builds `debug` (-O0), where
#    _FORTIFY_SOURCE has no effect and the server's startup hardening gate
#    refuses to start (ADR-0148).
CC=clang CXX=clang++ meson setup build-deb \
    --buildtype=release \
    --prefix=/usr \
    --sysconfdir=/etc \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie -Wl,-z,relro -Wl,-z,now' \
    -Dc_link_args='-pie -Wl,-z,relro -Wl,-z,now'

# 2. Compile
meson compile -C build-deb

# 3. Install into staging tree
# --skip-subprojects: the vendored sqlite3 archive and headers are build inputs,
# not files the package ships (as in every other package script).
meson install -C build-deb --destdir "$(pwd)/${STAGING}/" --skip-subprojects

# 4. Install systemd service unit
install -D -m 0644 packaging/systemd/merovingian.service \
    "${STAGING}/lib/systemd/system/merovingian.service"

# 5. Create config directory and install sample config
install -d -m 0755 "${STAGING}/etc/merovingian"
install -m 0644 config/merovingian.conf.example \
    "${STAGING}/etc/merovingian/merovingian.conf.example"

# 6. Install license
install -D -m 0644 LICENSE \
    "${STAGING}/usr/share/doc/${PKG_NAME}/copyright"

# 7. Work out the shared-library dependencies for the release this package is
#    built on (ADR-0650). A .deb installs only on the release it was built for,
#    and library package names differ between releases: Ubuntu 24.04 ships
#    libturbojpeg, not libturbojpeg0, and Ubuntu after 26.04 has no libssl3. So
#    no fixed list is right for all of them. dpkg-shlibdeps maps each NEEDED
#    entry of every shipped ELF file to the package that provides the library,
#    with the minimum version the binary's symbols require. It reads
#    debian/control, so it runs in a scratch directory holding a minimal one.
STAGING_ROOT="$(pwd)/${STAGING}"
ELF_FILES=$(find "${STAGING_ROOT}/usr" -type f | sort | while read -r file; do
    if [ "$(head -c 4 "${file}" | od -An -c | tr -d ' \n')" = "177ELF" ]; then
        printf '%s\n' "${file}"
    fi
done)
if [ -z "${ELF_FILES}" ]; then
    echo "build-deb.sh: the staging tree holds no ELF file" >&2
    exit 1
fi
SHLIBS_DIR=$(mktemp -d)
trap 'rm -rf "${SHLIBS_DIR}"' EXIT
mkdir "${SHLIBS_DIR}/debian"
printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "${PKG_NAME}" "${PKG_NAME}" \
    > "${SHLIBS_DIR}/debian/control"
# Word splitting on ELF_FILES is intended: one path per line, none with spaces.
# shellcheck disable=SC2086
SHLIBS_DEPENDS=$(cd "${SHLIBS_DIR}" && dpkg-shlibdeps -O ${ELF_FILES} | sed -n 's/^shlibs:Depends=//p')
if [ -z "${SHLIBS_DEPENDS}" ]; then
    echo "build-deb.sh: dpkg-shlibdeps found no shared-library dependencies" >&2
    exit 1
fi
echo "Shared-library dependencies: ${SHLIBS_DEPENDS}"

# 8. Generate binary DEBIAN/control
install -d "${STAGING}/DEBIAN"
ARCH=$(dpkg --print-architecture)
INSTALLED_SIZE=$(du -sk "${STAGING}" | cut -f1)
cat > "${STAGING}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: James Chapman <james@merovingian-homeserver.example>
Installed-Size: ${INSTALLED_SIZE}
Depends: adduser, ${SHLIBS_DEPENDS}
Recommends: ca-certificates
Section: net
Priority: optional
Description: A secure Matrix Protocol homeserver
 Merovingian is an alpha Matrix Protocol homeserver.
 Secure by design, implementation, and during runtime.
EOF

# 9. Copy maintainer scripts and conffiles
cp packaging/deb/postinst "${STAGING}/DEBIAN/postinst"
cp packaging/deb/prerm    "${STAGING}/DEBIAN/prerm"
cp packaging/deb/conffiles "${STAGING}/DEBIAN/conffiles"
chmod 0755 "${STAGING}/DEBIAN/postinst" "${STAGING}/DEBIAN/prerm"

# 10. Build .deb
dpkg-deb --root-owner-group --build "${STAGING}/" \
    "${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "Built: ${PKG_NAME}_${VERSION}_${ARCH}.deb"
