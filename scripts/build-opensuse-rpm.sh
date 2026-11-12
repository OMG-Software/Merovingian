#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build an RPM package for merovingian 0.12.93 on OpenSUSE Tumbleweed or Leap.
#
# Uses packaging/opensuse/merovingian.spec which adapts BuildRequires to
# OpenSUSE package names (libopenssl-devel, postgresql-devel, libpng16-devel,
# libjpeg8-devel, sqlite3-devel, ninja, pkgconf).
#
# The dist tag is forced so the filename is unambiguous in the release bundle
# alongside the Fedora and RHEL RPMs: .opensuse (Tumbleweed) unless
# MEROVINGIAN_RPM_DIST names another, as packages.yml does for Leap 16.0
# (.leap16, ADR-0650).
set -e

VERSION="0.12.93"
DIST="${MEROVINGIAN_RPM_DIST:-.opensuse}"
case "${DIST}" in
    .[a-z]*) ;;
    *)
        echo "MEROVINGIAN_RPM_DIST must start with a dot and a lower-case letter: ${DIST}" >&2
        exit 1
        ;;
esac
case "${DIST}" in
    *[!a-z0-9.]*)
        echo "MEROVINGIAN_RPM_DIST may hold only lower-case letters, digits and dots: ${DIST}" >&2
        exit 1
        ;;
esac

mkdir -p "${HOME}/rpmbuild/BUILD"
mkdir -p "${HOME}/rpmbuild/BUILDROOT"
mkdir -p "${HOME}/rpmbuild/RPMS"
mkdir -p "${HOME}/rpmbuild/SOURCES"
mkdir -p "${HOME}/rpmbuild/SPECS"
mkdir -p "${HOME}/rpmbuild/SRPMS"

tar czf "${HOME}/rpmbuild/SOURCES/merovingian-${VERSION}.tar.gz" \
    --transform "s|^\./|merovingian-${VERSION}/|" \
    --exclude='./.git' \
    --exclude='./build-opensuse-rpm' \
    --exclude='./staging-*' \
    .

cp packaging/opensuse/merovingian.spec "${HOME}/rpmbuild/SPECS/merovingian.spec"

rpmbuild -bb \
    --define "_topdir ${HOME}/rpmbuild" \
    --define "dist ${DIST}" \
    "${HOME}/rpmbuild/SPECS/merovingian.spec"

find "${HOME}/rpmbuild/RPMS" \
    -name "merovingian-${VERSION}*.rpm" \
    -exec cp {} . \;

echo "Built OpenSUSE RPM(s) for merovingian-${VERSION}"
