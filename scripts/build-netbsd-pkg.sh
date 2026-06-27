#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a NetBSD binary package (.tgz) for merovingian 0.10.3.
#
# The checked-in packaging/netbsd/Makefile is the pkgsrc recipe kept for
# downstream porters.  This script generates a framework-free package so CI
# builds and validates an installable artifact on every run.
#
# pkg_create from NetBSD 10.x base segfaults (SIGSEGV / ssh exit 139) when it
# scans hardened ELF binaries under QEMU.  We assemble the .tgz directly from
# a staged tree using tar, which produces a package that pkg_add can install.
set -e

VERSION="0.10.3"
STAGE="staging-netbsd"
PREFIX=/usr/pkg

# NetBSD's base compiler is GCC, which here predates C++26. Build with the
# pkgsrc clang toolchain unless the caller overrides CC/CXX.
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

rm -rf "${STAGE}" build-netbsd-pkg pkg-build "+CONTENTS" "+COMMENT" "+DESC" "+BUILD_INFO" \
    "merovingian-${VERSION}.tgz"

# 1. Configure + build with NetBSD/pkgsrc prefix conventions. forcefallback
#    vendors sqlite/yyjson; libcurl is a system dependency on every platform.
meson setup build-netbsd-pkg \
    --prefix="${PREFIX}" \
    --sysconfdir="${PREFIX}/etc" \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'

meson compile -C build-netbsd-pkg
# --skip-subprojects prevents vendored sqlite3 headers/archives from landing
# in the staging tree and confusing the package tool.
meson install -C build-netbsd-pkg --destdir "${PWD}/${STAGE}" --skip-subprojects

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

# 3. Package metadata (NetBSD pkg format).
printf '%s\n' "Secure Matrix Protocol homeserver" > "+COMMENT"
cat > "+DESC" <<'EOF'
Merovingian is an alpha Matrix Protocol homeserver focused on secure
implementation, runtime hardening, and auditable dependency boundaries.
EOF
{
    echo "MACHINE_ARCH=$(uname -p 2>/dev/null || uname -m)"
    echo "OPSYS=$(uname -s)"
    echo "OS_VERSION=$(uname -r)"
} > "+BUILD_INFO"

# +CONTENTS packing list: @name identifies the package, @cwd is the install
# prefix, files are relative to @cwd, @dir records directories to remove on
# deinstall.
cat > "+CONTENTS" <<EOF
@name merovingian-${VERSION}
@cwd ${PREFIX}
bin/merovingian-db-migrate
bin/merovingian-server
etc/merovingian/merovingian.conf.sample
libexec/merovingian/merovingian-thumbnail-worker
share/examples/rc.d/merovingian
@dir share/examples/rc.d
@dir share/examples
@dir libexec/merovingian
@dir etc/merovingian
EOF

# 4. Assemble the .tgz: meta-files first (pkg_add expects +CONTENTS, +COMMENT,
#    +DESC, +BUILD_INFO at the archive root), then the package files at their
#    install-relative paths.
PKGDIR="${PWD}/pkg-build"
mkdir -p \
    "${PKGDIR}/bin" \
    "${PKGDIR}/etc/merovingian" \
    "${PKGDIR}/libexec/merovingian" \
    "${PKGDIR}/share/examples/rc.d"

cp "+CONTENTS" "+COMMENT" "+DESC" "+BUILD_INFO" "${PKGDIR}/"
cp "${STAGE}${PREFIX}/bin/merovingian-db-migrate"        "${PKGDIR}/bin/"
cp "${STAGE}${PREFIX}/bin/merovingian-server"            "${PKGDIR}/bin/"
cp "${STAGE}${PREFIX}/etc/merovingian/merovingian.conf.sample" \
                                                          "${PKGDIR}/etc/merovingian/"
cp "${STAGE}${PREFIX}/libexec/merovingian/merovingian-thumbnail-worker" \
                                                          "${PKGDIR}/libexec/merovingian/"
cp "${STAGE}${PREFIX}/share/examples/rc.d/merovingian"   "${PKGDIR}/share/examples/rc.d/"

( cd "${PKGDIR}" && tar czf "${OLDPWD}/merovingian-${VERSION}.tgz" \
    +CONTENTS +COMMENT +DESC +BUILD_INFO \
    bin/merovingian-db-migrate \
    bin/merovingian-server \
    etc/merovingian/merovingian.conf.sample \
    libexec/merovingian/merovingian-thumbnail-worker \
    share/examples/rc.d/merovingian )

echo "Built NetBSD package for merovingian-${VERSION}"
