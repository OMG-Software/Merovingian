<!-- Maintained by hand. Add a line here in the same commit as a new ADR. -->
# Architecture Decision Records

## Accepted Records

* [0000 - Record architecture decisions](0000-record-architecture-decisions.md)
* [0001 - Use Markdown Architectural Decision Records](0001-use-markdown-architectural-decision-records.md)
* [0002 - Use an owner-tracking mutex for the runtime lock](0002-use-an-owner-tracking-mutex-for-the-runtime-lock.md)
* [0003 - Drain every recursion level in one release primitive](0003-drain-every-recursion-level-in-one-release-primitive.md)
* [0004 - Release the runtime lock through the mutex, not through a guard](0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md)
* [0005 - Open the lock release scope at the blocking callee](0005-open-the-lock-release-scope-at-the-blocking-callee.md)
* [0006 - Extract released regions that produce values into functions](0006-extract-released-regions-that-produce-values-into-functions.md)
* [0007 - Assert lock behaviour from another thread](0007-assert-lock-behaviour-from-another-thread.md)
* [0008 - Keep reject-unsafe exemptions line-scoped](0008-keep-reject-unsafe-exemptions-line-scoped.md)
* [0009 - Serialize inbound PDU ingestion on per-room stripes](0009-serialize-inbound-pdu-ingestion-on-per-room-stripes.md)
* [0010 - Run fire-and-forget work as parked futures](0010-run-fire-and-forget-work-as-parked-futures.md)
* [0011 - Split strict and general-purpose canonical JSON](0011-split-strict-and-general-purpose-canonical-json.md)
* [0012 - Format floats with a portable round-trip search](0012-format-floats-with-a-portable-round-trip-search.md)
* [0013 - Require a power level default when local state is absent](0013-require-a-power-level-default-when-local-state-is-absent.md)
* [0014 - Confine cryptographic primitives behind providers](0014-confine-cryptographic-primitives-behind-providers.md)
* [0015 - Keep the signing secret out of the federation worker](0015-keep-the-signing-secret-out-of-the-federation-worker.md)
* [0016 - Require a master key rather than storing secrets in plaintext](0016-require-a-master-key-rather-than-storing-secrets-in-plaintext.md)
* [0017 - Never regenerate a signing key silently](0017-never-regenerate-a-signing-key-silently.md)
* [0018 - Warn rather than abort when memory locking fails](0018-warn-rather-than-abort-when-memory-locking-fails.md)
* [0019 - Apply rate limiting before authentication](0019-apply-rate-limiting-before-authentication.md)
* [0020 - Keep rate limit counters in memory](0020-keep-rate-limit-counters-in-memory.md)
* [0021 - Deny when a rate limit policy cannot be resolved](0021-deny-when-a-rate-limit-policy-cannot-be-resolved.md)
* [0022 - Validate the forwarded client address](0022-validate-the-forwarded-client-address.md)
* [0023 - Give each thread its own outbound HTTP handle](0023-give-each-thread-its-own-outbound-http-handle.md)
* [0024 - Decode untrusted images in a sandboxed child process](0024-decode-untrusted-images-in-a-sandboxed-child-process.md)
* [0025 - Return not found rather than the original on thumbnail failure](0025-return-not-found-rather-than-the-original-on-thumbnail-failure.md)
* [0026 - Refuse media uploads at capacity rather than evicting](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md)
* [0027 - Bound the connection queue but not the IPC queue](0027-bound-the-connection-queue-but-not-the-ipc-queue.md)
* [0028 - Drop push deliveries at the concurrency cap](0028-drop-push-deliveries-at-the-concurrency-cap.md)
* [0029 - Bound pusher delivery rather than registration](0029-bound-pusher-delivery-rather-than-registration.md)
* [0030 - Key the pre-auth key resolution budget on source address](0030-key-the-pre-auth-key-resolution-budget-on-source-address.md)
* [0031 - Store narrow purpose tokens in separate tables](0031-store-narrow-purpose-tokens-in-separate-tables.md)
* [0032 - Throttle failed logins per claimed account](0032-throttle-failed-logins-per-claimed-account.md)
* [0033 - Leave SSO protocol integration to an operator gateway](0033-leave-sso-protocol-integration-to-an-operator-gateway.md)
* [0034 - Use a longer login token window than the spec suggests](0034-use-a-longer-login-token-window-than-the-spec-suggests.md)
* [0035 - Parse appservice registrations as a bounded YAML subset](0035-parse-appservice-registrations-as-a-bounded-yaml-subset.md)
* [0036 - Match appservice namespaces against whole identifiers](0036-match-appservice-namespaces-against-whole-identifiers.md)
* [0037 - Detect namespace conflicts by comparing pattern strings](0037-detect-namespace-conflicts-by-comparing-pattern-strings.md)
* [0038 - Degrade third party lookups instead of failing them](0038-degrade-third-party-lookups-instead-of-failing-them.md)
* [0039 - Populate the full device list on an initial sync](0039-populate-the-full-device-list-on-an-initial-sync.md)
* [0040 - Transfer PostgreSQL ownership with a scoped statement](0040-transfer-postgresql-ownership-with-a-scoped-statement.md)
* [0041 - Refuse to start the federation worker unsandboxed](0041-refuse-to-start-the-federation-worker-unsandboxed.md)
* [0042 - Spawn the federation worker with a minimal environment](0042-spawn-the-federation-worker-with-a-minimal-environment.md)
* [0043 - Base64 encode IPC response bodies](0043-base64-encode-ipc-response-bodies.md)
* [0044 - Wipe secrets with an optimisation barrier](0044-wipe-secrets-with-an-optimisation-barrier.md)
* [0045 - Ship a static musl tarball as the portability fallback](0045-ship-a-static-musl-tarball-as-the-portability-fallback.md)
* [0046 - Request FORTIFY_SOURCE only on optimised builds](0046-request-fortify-source-only-on-optimised-builds.md)
* [0047 - Keep project phase out of the version string](0047-keep-project-phase-out-of-the-version-string.md)
* [0048 - Treat soak and load runs as release evidence not CI](0048-treat-soak-and-load-runs-as-release-evidence-not-ci.md)
* [0049 - Treat the specification as the conformance authority](0049-treat-the-specification-as-the-conformance-authority.md)
* [0050 - Use real dependencies in integration tests](0050-use-real-dependencies-in-integration-tests.md)
* [0051 - Document inert configuration keys rather than removing them](0051-document-inert-configuration-keys-rather-than-removing-them.md)
* [0052 - Revocation of credentials is one-way](0052-revocation-of-credentials-is-one-way.md)
* [0053 - The thumbnail decoder gets its own syscall profile](0053-the-thumbnail-decoder-gets-its-own-syscall-profile.md)
* [0054 - TLS sockets stay non-blocking for the life of the connection](0054-tls-sockets-stay-non-blocking-for-the-life-of-the-connection.md)
* [0055 - Filter all diagnostics and preserve audits](0055-filter-all-diagnostics-and-preserve-audits.md)
* [0056 - Use a thumbnail-specific rate limit](0056-use-a-thumbnail-specific-rate-limit.md)
* [0057 - UIAA sessions are in-memory and single-stage](0057-uiaa-sessions-are-in-memory-and-single-stage.md)
* [0058 - A suspended account may still refresh its access token](0058-a-suspended-account-may-still-refresh-its-access-token.md)
* [0059 - Serialise migrations per backend, not per abstraction](0059-serialise-migrations-per-backend-not-per-abstraction.md)
* [0060 - Show an uploaded key signature only to the audience its uploader has](0060-show-an-uploaded-key-signature-only-to-its-owner-audience.md)
* [0061 - Proxy remote cross-signing keys rather than caching them](0061-proxy-remote-cross-signing-keys-rather-than-caching-them.md)

## Rejected Records

* None

## Superseded Records

* None

## Deprecated Records

* None

## Records with non-standard statuses

* None
