#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build an RPM package for merovingian 0.4.50 using rpmbuild.
set -e

VERSION="0.4.50"

# 1. Create rpmbuild directory tree
mkdir -p "${HOME}/rpmbuild/BUILD"
mkdir -p "${HOME}/rpmbuild/BUILDROOT"
mkdir -p "${HOME}/rpmbuild/RPMS"
mkdir -p "${HOME}/rpmbuild/SOURCES"
mkdir -p "${HOME}/rpmbuild/SPECS"
mkdir -p "${HOME}/rpmbuild/SRPMS"

# 2. Create source tarball from the working tree.
# git-archive is unreliable in Docker containers (GIT_DISCOVERY_ACROSS_FILESYSTEM);
# tar from the working directory is equivalent and container-safe.
tar czf "${HOME}/rpmbuild/SOURCES/merovingian-${VERSION}.tar.gz" \
    --transform "s|^\./|merovingian-${VERSION}/|" \
    --exclude='./.git' \
    --exclude='./build-rpm' \
    --exclude='./staging-*' \
    .

# 3. Copy spec file
cp packaging/rpm/merovingian.spec "${HOME}/rpmbuild/SPECS/merovingian.spec"

# 4. Build binary RPM
rpmbuild -bb \
    --define "_topdir ${HOME}/rpmbuild" \
    "${HOME}/rpmbuild/SPECS/merovingian.spec"

# 5. Copy resulting RPM(s) to the current directory
find "${HOME}/rpmbuild/RPMS" \
    -name "merovingian-${VERSION}*.rpm" \
    -exec cp {} . \;

echo "Built RPM(s) for merovingian-${VERSION}"
