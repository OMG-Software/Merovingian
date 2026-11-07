#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build for merovingian 0.12.81.
set -e

VERSION="0.12.81"
STAGING="staging-fbsd"

# Clean any state (staged files, build dir) from cached FreeBSD VM runs.
rm -rf "${STAGING}" "${STAGING}.metadata" build-freebsd-pkg

# 1. Configure with meson using FreeBSD prefix conventions.
#    -pie: produce a PIE executable so the kernel applies ASLR.
#    --buildtype=release: Meson otherwise builds `debug` (-O0), where
#    _FORTIFY_SOURCE has no effect and the server's startup hardening gate
#    refuses to start (ADR-0148).
meson setup build-freebsd-pkg \
    --buildtype=release \
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
meson install -C build-freebsd-pkg --destdir "${PWD}/${STAGING}" --skip-subprojects

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

# 6. Patch manifest version into a metadata directory alongside (not inside) the
#    staging root. Anchored to the top-level key: each dependency carries a
#    version of its own on its line, which must stay its minimum.
METADATA="${PWD}/${STAGING}.metadata"
mkdir -p "${METADATA}"
sed "s/^version: \"[^\"]*\"/version: \"${VERSION}\"/" \
    packaging/freebsd/+MANIFEST > "${METADATA}/+MANIFEST"

# 7. Generate the packing list from the staged tree. pkg-create(8) packages only
#    what a plist or the manifest lists: without one the result is a valid archive
#    holding no files. Paths are relative to the manifest's prefix, and every file
#    is owned by root, because an entry naming no owner keeps the build user's.
PLIST="${PWD}/${STAGING}.plist"
( cd "${STAGING}/usr/local" && find . -type f | sed 's|^\./||' | sort ) |
    while read -r file; do
        mode="$(stat -f '%Lp' "${STAGING}/usr/local/${file}")"
        printf '@(root,wheel,%s) %s\n' "${mode}" "${file}"
    done > "${PLIST}"

echo "[debug] packing list:"
cat "${PLIST}"

# 8. Create the .pkg archive. pkg-create(8) documents --plist only with --metadata,
#    not with --manifest. The root directory is the staging root, not its usr/local:
#    pkg appends the manifest's prefix to each plist path itself.
pkg create \
    --metadata "${METADATA}" \
    --plist "${PLIST}" \
    --root-dir "${PWD}/${STAGING}" \
    --out-dir .

# 9. Refuse a package that lacks anything an install needs.
PACKAGE="merovingian-${VERSION}.pkg"
LISTING="$(pkg info -l -F "${PACKAGE}")"
for required in \
    /usr/local/bin/merovingian-server \
    /usr/local/bin/merovingian-db-migrate \
    /usr/local/libexec/merovingian/merovingian-fed-worker \
    /usr/local/libexec/merovingian/merovingian-thumbnail-worker \
    /usr/local/etc/rc.d/merovingian \
    /usr/local/etc/merovingian/merovingian.conf.sample; do
    case "${LISTING}" in
        *"${required}"*) ;;
        *)
            echo "${PACKAGE} does not contain ${required}" >&2
            exit 1
            ;;
    esac
done

echo "Built FreeBSD package (static deps) for merovingian-${VERSION}"
