#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a Debian binary package (.deb) for merovingian 0.2.2.
set -e

VERSION="0.2.2"
PKG_NAME="merovingian"
STAGING="staging-deb"

# 1. Configure with meson.
#    --wrap-mode=forcefallback: app-level deps (SQLite, curl, yyjson) are
#    built from source-pinned wraps; OS-supplied security libs (OpenSSL,
#    libsodium, libpq) are resolved from the system with allow_fallback=false.
#    -pie: position-independent executable so the kernel applies ASLR.
CC=clang CXX=clang++ meson setup build-deb \
    --prefix=/usr \
    --sysconfdir=/etc \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'

# 2. Compile
meson compile -C build-deb

# 3. Install into staging tree
meson install -C build-deb --destdir "$(pwd)/${STAGING}/"

# 4. Install systemd service unit
install -D -m 0644 packaging/systemd/merovingian.service \
    "${STAGING}/lib/systemd/system/merovingian.service"

# 5. Create config directory placeholder
install -d -m 0755 "${STAGING}/etc/merovingian"

# 6. Install license
install -D -m 0644 LICENSE \
    "${STAGING}/usr/share/doc/${PKG_NAME}/copyright"

# 7. Generate binary DEBIAN/control
install -d "${STAGING}/DEBIAN"
ARCH=$(dpkg --print-architecture)
INSTALLED_SIZE=$(du -sk "${STAGING}" | cut -f1)
cat > "${STAGING}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: James Chapman <james@merovingian-homeserver.example>
Installed-Size: ${INSTALLED_SIZE}
Depends: libssl3, libsodium23, libpq5
Recommends: ca-certificates
Section: net
Priority: optional
Description: A secure Matrix Protocol homeserver
 Merovingian is an alpha Matrix Protocol homeserver.
 Secure by design, implementation, and during runtime.
EOF

# 8. Copy maintainer scripts and conffiles
cp packaging/deb/postinst "${STAGING}/DEBIAN/postinst"
cp packaging/deb/prerm    "${STAGING}/DEBIAN/prerm"
cp packaging/deb/conffiles "${STAGING}/DEBIAN/conffiles"
chmod 0755 "${STAGING}/DEBIAN/postinst" "${STAGING}/DEBIAN/prerm"

# 9. Build .deb
dpkg-deb --root-owner-group --build "${STAGING}/" \
    "${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "Built: ${PKG_NAME}_${VERSION}_${ARCH}.deb"
