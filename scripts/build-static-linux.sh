#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a portable Linux fallback tarball with musl-linked static PIE binaries.
set -eu

VERSION="${MEROVINGIAN_VERSION:-0.8.12}"
BUILD_DIR="${BUILD_DIR:-build-static-linux}"
STAGING="staging-static-linux"
PACKAGE_ROOT="merovingian-${VERSION}-linux-static-x86_64"
TARBALL="${PACKAGE_ROOT}.tar.gz"

rm -rf "$BUILD_DIR" "$STAGING" "$PACKAGE_ROOT" "$TARBALL" "${TARBALL}.sha256"

# Alpine ships libpsl, libunistring, and libidn2 as shared-only libraries;
# no static archives are available. curl's pkg-config lists them under
# Libs.private for static linking even though Alpine's libcurl.a was built
# without those features at the .a level. Strip them from a temp overlay so
# Meson does not emit unresolvable -lpsl/-lunistring/-lidn2 link flags.
_curl_pc_dir=$(pkg-config --variable=pcfiledir libcurl 2>/dev/null || true)
if [ -n "$_curl_pc_dir" ] && [ -f "$_curl_pc_dir/libcurl.pc" ]; then
    _patch_dir=$(mktemp -d)
    sed 's/ -lpsl\b//g; s/ -lunistring\b//g; s/ -lidn2\b//g' \
        "$_curl_pc_dir/libcurl.pc" > "$_patch_dir/libcurl.pc"
    PKG_CONFIG_PATH="${_patch_dir}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export PKG_CONFIG_PATH
fi

CC="${CC:-clang}" CXX="${CXX:-clang++}" meson setup "$BUILD_DIR" \
    --prefix=/usr \
    --wrap-mode=forcefallback \
    --prefer-static \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args=-static-pie \
    -Dc_link_args=-static-pie

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
