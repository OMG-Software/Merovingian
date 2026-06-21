#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build an RPM package for merovingian 0.9.7 targeting RHEL 10 / AlmaLinux 10.
#
# Differs from build-rpm.sh only in the spec file used: packaging/rhel/merovingian.spec
# omits catch-devel from BuildRequires (Catch2 is not reliably available in EPEL 10
# and is not needed when -Dbuild_tests=false).
set -e

VERSION="0.9.7"

mkdir -p "${HOME}/rpmbuild/BUILD"
mkdir -p "${HOME}/rpmbuild/BUILDROOT"
mkdir -p "${HOME}/rpmbuild/RPMS"
mkdir -p "${HOME}/rpmbuild/SOURCES"
mkdir -p "${HOME}/rpmbuild/SPECS"
mkdir -p "${HOME}/rpmbuild/SRPMS"

tar czf "${HOME}/rpmbuild/SOURCES/merovingian-${VERSION}.tar.gz" \
    --transform "s|^\./|merovingian-${VERSION}/|" \
    --exclude='./.git' \
    --exclude='./build-rhel-rpm' \
    --exclude='./staging-*' \
    .

cp packaging/rhel/merovingian.spec "${HOME}/rpmbuild/SPECS/merovingian.spec"

rpmbuild -bb \
    --define "_topdir ${HOME}/rpmbuild" \
    "${HOME}/rpmbuild/SPECS/merovingian.spec"

find "${HOME}/rpmbuild/RPMS" \
    -name "merovingian-${VERSION}*.rpm" \
    -exec cp {} . \;

echo "Built RHEL RPM(s) for merovingian-${VERSION}"
