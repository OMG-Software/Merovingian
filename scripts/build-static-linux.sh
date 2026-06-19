#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a portable Linux fallback tarball with musl-linked static PIE binaries.
set -eu

VERSION="${MEROVINGIAN_VERSION:-0.9.0}"
BUILD_DIR="${BUILD_DIR:-build-static-linux}"
STAGING="staging-static-linux"
PACKAGE_ROOT="merovingian-${VERSION}-linux-static-x86_64"
TARBALL="${PACKAGE_ROOT}.tar.gz"

rm -rf "$BUILD_DIR" "$STAGING" "$PACKAGE_ROOT" "$TARBALL" "${TARBALL}.sha256"

CC="${CC:-clang}" CXX="${CXX:-clang++}" meson setup "$BUILD_DIR" \
    --prefix=/usr \
    --wrap-mode=forcefallback \
    --prefer-static \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dstatic_curl_wrap=true \
    -Dcpp_link_args='-static-pie -Wl,-z,relro -Wl,-z,now' \
    -Dc_link_args='-static-pie -Wl,-z,relro -Wl,-z,now'

meson compile -C "$BUILD_DIR"
meson install -C "$BUILD_DIR" --destdir "$(pwd)/${STAGING}/"

for binary in "${STAGING}/usr/bin/merovingian-server" "${STAGING}/usr/bin/merovingian-db-migrate"; do
    if readelf -l "$binary" | grep -q "Requesting program interpreter"; then
        printf 'static fallback binary still has a dynamic interpreter: %s\n' "$binary" >&2
        exit 1
    fi
done

install -d -m 0755 "${PACKAGE_ROOT}/bin" "${PACKAGE_ROOT}/config" "${PACKAGE_ROOT}/docs"
install -m 0755 "${STAGING}/usr/bin/merovingian-server" "${PACKAGE_ROOT}/bin/"
install -m 0755 "${STAGING}/usr/bin/merovingian-db-migrate" "${PACKAGE_ROOT}/bin/"
install -m 0644 config/merovingian.conf.example "${PACKAGE_ROOT}/config/merovingian.conf.example"
install -m 0644 README.md LICENSE "${PACKAGE_ROOT}/"
install -m 0644 docs/configuration.md docs/release-process.md \
    docs/security-review-checklist.md "${PACKAGE_ROOT}/docs/"

tar -czf "$TARBALL" "$PACKAGE_ROOT"
sha256sum "$TARBALL" > "${TARBALL}.sha256"

echo "Built static Linux fallback: $TARBALL"
