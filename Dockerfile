# SPDX-License-Identifier: GPL-3.0-or-later
#
# Both stages use debian:trixie-slim pinned by the digest of its
# multi-architecture index, so a re-pushed tag cannot change what is built or
# shipped. Refresh the digest deliberately; see docs/release-process.md.
#
# The image runs as an unprivileged user and cannot drop the capability
# bounding set itself, so the startup hardening gate only passes when the
# container is started with every capability dropped:
#
#   docker run --cap-drop=ALL --security-opt=no-new-privileges ...

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS build

# The same build dependencies as the debian-pkg job in
# .github/workflows/packages.yml. libpng and libturbojpeg are required: without
# them Meson silently skips the thumbnail worker.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        bison \
        ca-certificates \
        clang \
        flex \
        gcc \
        git \
        m4 \
        make \
        meson \
        ninja-build \
        perl \
        pkg-config \
        libcurl4-openssl-dev \
        libpng-dev \
        libpq-dev \
        libsodium-dev \
        libssl-dev \
        libturbojpeg0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
# --buildtype=release: Meson otherwise builds `debug` (-O0), where
# _FORTIFY_SOURCE has no effect and the server's startup hardening gate
# refuses to start (ADR-0148).
RUN CC=clang CXX=clang++ meson setup build \
        --buildtype=release \
        --prefix=/usr \
        --sysconfdir=/etc \
        --wrap-mode=forcefallback \
        -Dhardening=true \
        -Dbuild_tests=false \
        -Dbuild_fuzz=false \
    && meson compile -C build \
    && meson install -C build --destdir /pkgroot --skip-subprojects

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcurl4t64 \
        libpng16-16t64 \
        libpq5 \
        libsodium23 \
        libssl3t64 \
        libturbojpeg0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system merovingian \
    && useradd --system --gid merovingian --home-dir /var/lib/merovingian --no-create-home \
        --shell /usr/sbin/nologin merovingian \
    && install -d -o merovingian -g merovingian -m 0750 /etc/merovingian /var/lib/merovingian /var/log/merovingian

COPY --from=build /pkgroot/usr/bin/merovingian-server /usr/bin/merovingian-server
COPY --from=build /pkgroot/usr/bin/merovingian-db-migrate /usr/bin/merovingian-db-migrate
COPY --from=build /pkgroot/usr/libexec/merovingian/merovingian-fed-worker /usr/libexec/merovingian/merovingian-fed-worker
COPY --from=build /pkgroot/usr/libexec/merovingian/merovingian-thumbnail-worker /usr/libexec/merovingian/merovingian-thumbnail-worker
COPY config/merovingian.conf.example /etc/merovingian/merovingian.conf

# Fail the image build, rather than ship a binary that cannot start, if any
# shipped binary links a shared library the runtime stage does not install.
RUN for binary in \
        /usr/bin/merovingian-server \
        /usr/bin/merovingian-db-migrate \
        /usr/libexec/merovingian/merovingian-fed-worker \
        /usr/libexec/merovingian/merovingian-thumbnail-worker; do \
        if ldd "${binary}" | grep 'not found'; then \
            echo "unresolved shared library in ${binary}" >&2; \
            exit 1; \
        fi; \
    done

USER merovingian:merovingian
ENTRYPOINT ["/usr/bin/merovingian-server"]
CMD ["--config", "/etc/merovingian/merovingian.conf"]
