# SPDX-License-Identifier: GPL-3.0-or-later
#
# The Complement image (tests/complement/AGENTS.md): the Debian trixie package
# a release ships, installed unchanged on the base the shipped image uses,
# plus the test-only plumbing Complement needs (nginx, openssl, curl, setpriv
# and the entrypoint). Nothing is compiled here: Complement must test the
# binary that ships (ADR-0233).
#
#   cp merovingian_<version>_amd64-debian.deb tests/complement/artifact/merovingian.deb
#   docker build \
#       --build-arg MEROVINGIAN_DEB_SHA256=<the package's SHA-256> \
#       --tag merovingian-complement tests/complement
#
# The image starts as root on purpose; see entrypoint.sh.

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# The package's SHA-256: from the release's GPG-signed SHA256SUMS, or for a
# package built locally, sha256sum of it. The build refuses a package it was
# not told to expect.
ARG MEROVINGIAN_DEB_SHA256

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        nginx \
        openssl \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && command -v setpriv >/dev/null

COPY artifact/merovingian.deb /tmp/merovingian.deb
RUN if ! printf '%s\n' "${MEROVINGIAN_DEB_SHA256:-}" | grep -Eqx '[0-9a-f]{64}'; then \
        echo "MEROVINGIAN_DEB_SHA256 must be the package's SHA-256 (64 lowercase hex digits)" >&2; \
        exit 1; \
    fi \
    && printf '%s  %s\n' "${MEROVINGIAN_DEB_SHA256}" /tmp/merovingian.deb | sha256sum --check --strict - \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/merovingian.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/merovingian.deb

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh render-config.sh prepare-state.sh mint-tls.sh install-appservices.sh server-name.sh merovingian.conf.template /usr/local/lib/merovingian-complement/
RUN chmod 0755 /usr/local/lib/merovingian-complement/*.sh \
    && chmod 0644 /usr/local/lib/merovingian-complement/merovingian.conf.template /etc/nginx/nginx.conf \
    && nginx -t -q

EXPOSE 8008 8448

# Healthy once the client API answers through nginx, which also means the
# server has passed its startup hardening self-check.
HEALTHCHECK --interval=1s --timeout=5s --start-period=60s --retries=3 \
    CMD curl --fail --silent --max-time 4 --output /dev/null http://127.0.0.1:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/usr/local/lib/merovingian-complement/entrypoint.sh"]
