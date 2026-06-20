## 0.9.1

### Fixed
- **fix(http): wire TLS sync pool to eliminate main-pool starvation and federated E2EE key-share delay:** `serve_tls_http` now passes `sync_pool` and a TLS-aware write callback through to `serve_stream`. TLS long-poll `/sync` connections are offloaded to the dedicated 32-thread sync pool identically to the plain-HTTP path, freeing main pool threads for federation requests. Previously the `sync_pool` parameter was silently discarded (`/*sync_pool*/`), causing all TLS long-poll connections to block main pool threads for up to 30 seconds. This starved federation transaction processing, delaying delivery of `m.direct_to_device` key-share EDUs and producing the observable symptom of taking up to 30 seconds to decrypt a newly-joined federated user's replies. `TlsConnectionStream` is updated to hold `shared_ptr<TlsConnection>` so the TLS state can be shared safely between the read phase (main pool thread) and the async write phase (sync pool thread). The sync wait cap remains 5 seconds, matching the plain-HTTP path.

## 0.9.0

### Fixed
- **fix(auth): include `soft_logout: true` in 401 responses for expired access tokens (spec §5.7.2):** when an access token is found-but-expired the server now returns `{"errcode":"M_UNKNOWN_TOKEN","error":"unauthenticated","soft_logout":true}` so Matrix clients use their refresh token rather than performing a full session logout. Revoked tokens continue to return a plain 401 without `soft_logout`, preserving hard-logout semantics for explicit revocations.

### Changed
- **chore(release): beta milestone — promote from pre-beta (0.8.x) to beta phase (0.9.0):** version number advanced to 0.9.0 per the versioning scheme phase markers. No functional changes; this commit updates all version strings across `meson.build`, source files, packaging metadata, and build scripts.
- **docs: update README to reflect beta status:** banner note and Project Status section updated from pre-beta/in-development language to beta; pre-beta changelog history archived to `CHANGELOG-pre-beta.md`.
