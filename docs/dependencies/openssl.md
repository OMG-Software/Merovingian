# OpenSSL dependency review

This note records the dependency review for OpenSSL.

## Decision

OpenSSL is accepted as the selected TLS provider for runtime listener TLS. It is
wrapped behind `merovingian::homeserver` TLS context and connection types and
must not leak OpenSSL handles into routing, client-server, federation, or room
logic.

## Why it is needed

Matrix federation and public client listeners require a TLS implementation.
OpenSSL is packaged across the supported Linux and BSD targets and has a Meson
WrapDB fallback for bootstrap builds when a system package is unavailable.

## Security boundary

- `SSL_CTX` and `SSL` ownership is RAII-managed inside the TLS implementation.
- Listener startup fails closed when OpenSSL initialization, certificate loading,
  private-key loading, or key/certificate matching fails.
- TLS handshakes use the existing bounded connection timeout.
- The server enforces TLS 1.2 or newer.
- OpenSSL headers are resolved as system includes when provided by the host.

## Maintenance and platform posture

System OpenSSL packages are preferred for production builds so operating-system
security updates carry the patch burden. The pinned Meson wrap exists for
bootstrap and CI reproducibility, not as a policy to vendor OpenSSL in release
builds.

## Current limitations

- Certificate reload remains restart-bound.
- Remote federation TLS verification and key discovery are still separate work.
