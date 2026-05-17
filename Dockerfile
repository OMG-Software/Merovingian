# SPDX-License-Identifier: GPL-3.0-or-later

FROM debian:trixie-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        git \
        libcurl4-openssl-dev \
        libsodium-dev \
        meson \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN meson setup build -Dbuild_tests=false -Dbuild_fuzz=false --prefix=/usr \
    && meson compile -C build \
    && meson install -C build --destdir /pkgroot

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcurl4 libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system merovingian \
    && adduser --system --ingroup merovingian --home /var/lib/merovingian --no-create-home merovingian \
    && install -d -o merovingian -g merovingian -m 0750 /etc/merovingian /var/lib/merovingian /var/log/merovingian

COPY --from=build /pkgroot/usr/bin/merovingian-server /usr/bin/merovingian-server
COPY config/merovingian.conf.example /etc/merovingian/merovingian.conf

USER merovingian:merovingian
ENTRYPOINT ["/usr/bin/merovingian-server"]
CMD ["--config", "/etc/merovingian/merovingian.conf"]
