#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build an RPM package for merovingian 0.9.3 on OpenSUSE Tumbleweed.
#
# Uses packaging/opensuse/merovingian.spec which adapts BuildRequires to
# OpenSUSE package names (libopenssl-devel, postgresql-devel, libpng16-devel,
# libjpeg8-devel, sqlite3-devel, ninja, pkgconf).
#
# The dist tag is forced to .opensuse so the filename is unambiguous in the
# release bundle alongside the Fedora and RHEL RPMs.
set -e

VERSION="0.9.3"

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
    --define "dist .opensuse" \
    "${HOME}/rpmbuild/SPECS/merovingian.spec"

find "${HOME}/rpmbuild/RPMS" \
    -name "merovingian-${VERSION}*.rpm" \
    -exec cp {} . \;

echo "Built OpenSUSE RPM(s) for merovingian-${VERSION}"
