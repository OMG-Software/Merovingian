#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Stage a release tarball's directory from a configured, compiled Meson build
# (ADR-0597).
#
# Usage: stage-release-tarball.sh BUILD_DIR PACKAGE_ROOT
#
# The binaries come from `meson install`, not a list of names, so every
# executable the build installs ships: bin/ holds what Meson installs to
# <prefix>/bin and libexec/merovingian/ what it installs to
# <prefix>/libexec/merovingian. The server and the thumbnail worker look for
# their helpers under the build's own <prefix>/libexec/merovingian, so the
# prefix is recorded in PACKAGE_ROOT/INSTALL-PREFIX.
#
# Refuses (exit 1) when PACKAGE_ROOT already exists or any of the four
# executables a release must carry is missing. Re-runnable once PACKAGE_ROOT
# has been removed.
set -eu

fail() {
    printf 'stage-release-tarball.sh: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: stage-release-tarball.sh BUILD_DIR PACKAGE_ROOT"
build_dir=$1
package_root=$2

[ -d "$build_dir" ] || fail "build directory $build_dir does not exist"
[ ! -e "$package_root" ] || fail "$package_root already exists"

staging="${package_root}.staging"
rm -rf "$staging"
# --skip-subprojects: the vendored SQLite archive and headers are build inputs,
# not files a release ships (as in every package script).
meson install -C "$build_dir" --destdir "$(pwd)/${staging}" --skip-subprojects

servers=$(find "$staging" -type f -path '*/bin/merovingian-server')
[ -n "$servers" ] || fail "meson install did not install merovingian-server"
[ "$(printf '%s\n' "$servers" | wc -l | tr -d ' ')" -eq 1 ] || fail "more than one merovingian-server was installed"
installed_prefix=${servers%/bin/merovingian-server}
prefix=${installed_prefix#"${staging}"}

for required in bin/merovingian-server bin/merovingian-db-migrate \
    libexec/merovingian/merovingian-fed-worker libexec/merovingian/merovingian-thumbnail-worker; do
    [ -f "${installed_prefix}/${required}" ] || fail "the build did not install ${required}"
done

mkdir -p "${package_root}/bin" \
    "${package_root}/libexec/merovingian" \
    "${package_root}/config" \
    "${package_root}/docs" \
    "${package_root}/packaging/deb" \
    "${package_root}/packaging/rpm" \
    "${package_root}/packaging/freebsd" \
    "${package_root}/packaging/openbsd" \
    "${package_root}/packaging/netbsd" \
    "${package_root}/packaging/systemd" \
    "${package_root}/packaging/openrc" \
    "${package_root}/packaging/rc.d"
cp -p "${installed_prefix}/bin/"* "${package_root}/bin/"
cp -p "${installed_prefix}/libexec/merovingian/"* "${package_root}/libexec/merovingian/"
printf '%s\n' "$prefix" > "${package_root}/INSTALL-PREFIX"
cp config/merovingian.conf.example "${package_root}/config/"
cp LICENSE README.md "${package_root}/"
cp docs/user-manual.md docs/release-process.md docs/security-review-checklist.md "${package_root}/docs/"
cp packaging/systemd/merovingian.service "${package_root}/packaging/systemd/"
cp packaging/openrc/merovingian "${package_root}/packaging/openrc/"
cp packaging/rc.d/merovingian "${package_root}/packaging/rc.d/"
cp packaging/deb/control "${package_root}/packaging/deb/"
cp packaging/rpm/merovingian.spec "${package_root}/packaging/rpm/"
cp packaging/freebsd/+MANIFEST "${package_root}/packaging/freebsd/"
cp packaging/openbsd/DESCR packaging/openbsd/PLIST "${package_root}/packaging/openbsd/"
cp packaging/netbsd/Makefile "${package_root}/packaging/netbsd/"
rm -rf "$staging"

printf 'Staged %s from %s (install prefix %s):\n' "$package_root" "$build_dir" "$prefix"
find "${package_root}/bin" "${package_root}/libexec" -type f | sort
