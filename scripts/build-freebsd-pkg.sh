#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a FreeBSD pkg(8) package for merovingian 0.3.0.
set -e

VERSION="0.3.0"
STAGING="staging-fbsd"

# Clean any state (staged files, build dir) from cached FreeBSD VM runs.
rm -rf "${STAGING}" build-freebsd-pkg

# 1. Configure with meson using FreeBSD prefix conventions.
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

# 3. Install into staging tree.
#    $PWD avoids subshell/symlink issues that $(pwd) can have inside the VM.
meson install -C build-freebsd-pkg --destdir "${PWD}/${STAGING}"

# 4. Install rc.d script and sample config (BSD install does not accept GNU -D)
mkdir -p "${STAGING}/usr/local/etc/rc.d"
install -m 0755 packaging/rc.d/merovingian \
    "${STAGING}/usr/local/etc/rc.d/merovingian"
mkdir -p "${STAGING}/usr/local/etc/merovingian"
install -m 0644 config/merovingian.conf.example \
    "${STAGING}/usr/local/etc/merovingian/merovingian.conf.sample"

# 5. Confirm the staged tree looks right before packaging.
echo "[debug] staged files under ${STAGING}/usr/local:"
ls -lR "${STAGING}/usr/local" || true

# 6. Patch manifest version into a temp file alongside (not inside) the staging root.
MANIFEST="${PWD}/${STAGING}.manifest"
sed "s/version: \"[^\"]*\"/version: \"${VERSION}\"/" \
    packaging/freebsd/+MANIFEST > "${MANIFEST}"

# 7. Create the .pkg archive.
#    No --plist: pkg(8) automatically packages all files found under --root-dir.
pkg create \
    --manifest "${MANIFEST}" \
    --root-dir "${PWD}/${STAGING}/usr/local" \
    --out-dir .

echo "Built FreeBSD package (static deps) for merovingian-${VERSION}"
