#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a FreeBSD pkg(8) package for merovingian 0.2.1.
set -e

VERSION="0.2.1"
STAGING="staging-fbsd"

# Wipe any stale staging tree left by a cached FreeBSD VM from a previous run.
rm -rf "${STAGING}"

# 1. Configure with meson using FreeBSD prefix conventions.
#    --prefer-static: link .a archives for application deps; libc stays dynamic.
#    -pie: produce a PIE executable so the kernel applies ASLR.
meson setup build-freebsd-pkg \
    --prefix=/usr/local \
    --sysconfdir=/usr/local/etc \
    --wrap-mode=default \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'

# 2. Compile
meson compile -C build-freebsd-pkg

# 3. Install into staging tree
meson install -C build-freebsd-pkg --destdir "$(pwd)/${STAGING}/"

# 4. Install rc.d script (BSD install does not accept GNU -D; create dir first)
mkdir -p "${STAGING}/usr/local/etc/rc.d"
install -m 0755 packaging/rc.d/merovingian \
    "${STAGING}/usr/local/etc/rc.d/merovingian"

# 5. Generate plist from installed files (relative to root-dir)
#    Use paths inside ${STAGING} (wiped above) not /tmp, so cached VM state
#    from previous runs cannot bleed into this run.
STAGING_ROOT="$(pwd)/${STAGING}/usr/local"
PLIST="$(pwd)/${STAGING}/merovingian.plist"
MANIFEST="$(pwd)/${STAGING}/merovingian-manifest"

echo "[debug] staging tree:"
find "${STAGING_ROOT}" -type f || true
(cd "${STAGING_ROOT}" && find . -type f | sed 's|^\./||' | sort) > "${PLIST}"
echo "[debug] plist:"
cat "${PLIST}"

# 6. Patch manifest version
sed "s/version: \"[^\"]*\"/version: \"${VERSION}\"/" \
    packaging/freebsd/+MANIFEST > "${MANIFEST}"

# 7. Create the .pkg archive
pkg create \
    --manifest "${MANIFEST}" \
    --root-dir "${STAGING_ROOT}" \
    --plist "${PLIST}" \
    --out-dir .

echo "Built FreeBSD package (static deps) for merovingian-${VERSION}"
