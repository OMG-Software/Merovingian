#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a NetBSD binary package (.tgz) for merovingian 0.8.12.
#
# Standalone pkg_create(1) from pkgtools/pkg_install — no pkgsrc tree. The
# checked-in packaging/netbsd/Makefile is the pkgsrc recipe kept for downstream;
# this script generates a framework-free package so CI builds and validates an
# installable artifact on every run.
set -e

VERSION="0.8.12"
STAGE="staging-netbsd"
PREFIX=/usr/pkg

# NetBSD's base compiler is GCC, which here predates C++26. Build with the
# pkgsrc clang toolchain unless the caller overrides CC/CXX.
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

rm -rf "${STAGE}" build-netbsd-pkg pkg-plist-netbsd "merovingian-${VERSION}.tgz"

# 1. Configure + build with NetBSD/pkgsrc prefix conventions. libcurl is a
#    system dependency on every platform, so forcefallback only vendors
#    sqlite/yyjson and never tries to build curl from source.
meson setup build-netbsd-pkg \
    --prefix="${PREFIX}" \
    --sysconfdir="${PREFIX}/etc" \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false

meson compile -C build-netbsd-pkg
meson install -C build-netbsd-pkg --destdir "${PWD}/${STAGE}"

# 2. rc.d example script (pkgsrc installs under share/examples/rc.d) with the
#    pkgsrc @PREFIX@/@PKG_SYSCONFDIR@ placeholders substituted; sample config.
install -d "${STAGE}${PREFIX}/share/examples/rc.d"
sed -e "s|@PREFIX@|${PREFIX}|g" -e "s|@PKG_SYSCONFDIR@|${PREFIX}/etc|g" \
    packaging/netbsd/files/merovingian.sh \
    > "${STAGE}${PREFIX}/share/examples/rc.d/merovingian"
chmod 0755 "${STAGE}${PREFIX}/share/examples/rc.d/merovingian"
install -d "${STAGE}${PREFIX}/etc/merovingian"
install -m 0644 config/merovingian.conf.example \
    "${STAGE}${PREFIX}/etc/merovingian/merovingian.conf.sample"

# 3. Metadata files required by pkg_create.
COMMENT="${PWD}/netbsd-comment"
DESC="${PWD}/netbsd-desc"
BUILD_INFO="${PWD}/netbsd-build-info"
printf '%s\n' "Secure Matrix Protocol homeserver" > "${COMMENT}"
cat > "${DESC}" <<'EOF'
Merovingian is an alpha Matrix Protocol homeserver focused on secure
implementation, runtime hardening, and auditable dependency boundaries.
EOF
{
    echo "MACHINE_ARCH=$(uname -p 2>/dev/null || uname -m)"
    echo "OPSYS=$(uname -s)"
    echo "OS_VERSION=$(uname -r)"
} > "${BUILD_INFO}"

# 4. Packing list (+CONTENTS) generated from the staged tree. Paths are relative
#    to the staging prefix; pkg_create reads them from -p (the staging tree) and
#    records them under -I (the real install prefix).
PLIST="${PWD}/pkg-plist-netbsd"
( cd "${STAGE}${PREFIX}" && find . -type f | sed 's|^\./||' | sort ) > "${PLIST}"

echo "[debug] staged tree under ${STAGE}:"
ls -lR "${STAGE}" || true
echo "[debug] packing list:"
cat "${PLIST}"

pkg_create \
    -p "${PWD}/${STAGE}${PREFIX}" \
    -I "${PREFIX}" \
    -c "${COMMENT}" \
    -d "${DESC}" \
    -B "${BUILD_INFO}" \
    -f "${PLIST}" \
    "merovingian-${VERSION}"

echo "Built NetBSD package for merovingian-${VERSION}"
