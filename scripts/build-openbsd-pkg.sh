#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build an OpenBSD binary package (.tgz) for merovingian 0.9.23.
#
# Standalone pkg_create(1) â€” no ports tree. The checked-in packaging/openbsd/PLIST
# is the ports-framework packing list kept for downstream porters; this script
# generates a framework-free packing list from the staged install so CI can
# produce and validate an installable package on every run.
set -e

VERSION="0.9.23"
STAGE="staging-openbsd"
PREFIX=/usr/local

rm -rf "${STAGE}" build-openbsd-pkg pkg-plist-openbsd "merovingian-${VERSION}.tgz"

# 1. Configure + build with OpenBSD prefix conventions.
meson setup build-openbsd-pkg \
    --prefix="${PREFIX}" \
    --sysconfdir=/etc \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'

meson compile -C build-openbsd-pkg
meson install -C build-openbsd-pkg --destdir "${PWD}/${STAGE}" --skip-subprojects

# 2. Stage the rc.d control script and sample config (outside ${PREFIX}).
install -d "${STAGE}/etc/rc.d"
install -m 0755 packaging/openbsd/rc.d/merovingian "${STAGE}/etc/rc.d/merovingian"
install -d "${STAGE}/etc/merovingian"
install -m 0644 config/merovingian.conf.example \
    "${STAGE}/etc/merovingian/merovingian.conf.sample"

# 3. Generate a framework-free packing list from the staged tree. User/group
#    creation is handled by packaging/openbsd/+INSTALL.
PLIST="${PWD}/pkg-plist-openbsd"
{
    echo "@comment pkgpath=net/merovingian"
    echo "@cwd ${PREFIX}"
    ( cd "${STAGE}${PREFIX}" && find . -type f | sed 's|^\./||' | sort )
    echo "@cwd /etc"
    echo "@rcscript /etc/rc.d/merovingian"
    echo "@sample merovingian/merovingian.conf.sample"
} > "${PLIST}"

echo "[debug] staged tree under ${STAGE}:"
ls -lR "${STAGE}" || true
echo "[debug] packing list:"
cat "${PLIST}"

# 4. Create the package. -B points pkg_create at the package skeleton (+INSTALL,
#    +DESC) and the staged file root.
cp packaging/openbsd/+INSTALL "${STAGE}/+INSTALL"
cp packaging/openbsd/DESCR "${STAGE}/+DESC"

pkg_create \
    -A "$(uname -m)" \
    -B "${PWD}/${STAGE}" \
    -d "${STAGE}/+DESC" \
    -D COMMENT="Secure Matrix Protocol homeserver" \
    -f "${PLIST}" \
    -p "${PREFIX}" \
    "merovingian-${VERSION}.tgz"

echo "Built OpenBSD package for merovingian-${VERSION}"
