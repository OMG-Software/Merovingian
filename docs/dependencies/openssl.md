# OpenSSL dependency review

This note records the dependency review for OpenSSL.

## Decision

OpenSSL is accepted as the selected TLS provider for runtime listener TLS. It is
wrapped behind `merovingian::homeserver` TLS context and connection types and
must not leak OpenSSL handles into routing, client-server, federation, or room
logic.

## Why it is needed

Matrix federation and public client listeners require a TLS implementation.
OpenSSL is packaged across the supported Linux and BSD targets. Merovingian
requires that OS-provided development package instead of falling back to a
vendored OpenSSL build.

## Security boundary

- `SSL_CTX` and `SSL` ownership is RAII-managed inside the TLS implementation.
- Listener startup fails closed when OpenSSL initialization, certificate loading,
  private-key loading, or key/certificate matching fails.
- TLS handshakes use the existing bounded connection timeout.
- The server enforces TLS 1.2 or newer.
- OpenSSL headers are resolved as system includes when provided by the host.

## Maintenance and platform posture

System OpenSSL packages are required for normal builds so operating-system
security updates carry the patch burden. The top-level Meson dependency sets
`allow_fallback: false`, which keeps OpenSSL dynamically linked from the host
package even when other dependencies are forced through source-pinned wraps.
The same OS-supplied dynamic-link policy now applies to LibSodium and
PostgreSQL libpq. Linux and Fedora CI install `libssl-dev` or `openssl-devel`;
FreeBSD CI installs the `openssl` package.

The OS package must be an OpenSSL branch that still receives security fixes:
the current upstream LTS (3.5), a newer supported release, or a distribution
package whose vendor backports fixes to an older branch. Upstream support for
the OpenSSL 3.0 LTS line has ended, so an unpatched upstream 3.0 build is not
acceptable for a deployment. OpenBSD builds against its base-system LibreSSL,
which follows the OpenBSD release's own support window.

There is no `subprojects/openssl.wrap`: a wrap for an `allow_fallback: false`
dependency is never fetched, so it would only be an unmaintained pin
([ADR-0218](../adr/0218-os-supplied-dependencies-carry-no-wrap.md)). For the
same reason nothing under the project's `include/` directory may shadow an
OpenSSL header, since every target compiles with `-I include` ahead of the
system include path.

## License

OpenSSL is dual-licensed under the Apache-2.0 license and the OpenSSL-3.0
license (`SPDX: Apache-2.0`). The Apache-2.0 license is compatible with
Merovingian's GPL-3.0-or-later distribution. OpenSSL is resolved from the
operating-system package.

## Current limitations

- Certificate reload remains restart-bound.
- Remote federation TLS verification and key discovery are still separate work.
