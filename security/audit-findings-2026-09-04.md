# Merovingian Security Audit Findings — 2026-09-04

**Branch:** `feature/security-audit-findings-2026-09-04`  
**Target version:** `0.12.5`  
**Authority:** Matrix v1.19 spec + project security rules (`docs/security-coding-rules.md`, `docs/threat-model.md`)  
**Methodology:** Multi-agent workflow across 12 security dimensions. Four dimensions (auth, federation inbound/outbound, event pipeline, HTTP/network boundary) did not complete due to API rate limits, and adversarial verification of most findings was incomplete. Treat this list as a strong signal for manual review, not as a final independently verified set.

---

## How another LLM should use this file

1. Work in priority order (`P0` → `P1` → `P2`). Each finding has a **Priority** field.
2. For each finding:
   - Read the cited file and line range.
   - Write a failing Catch2 BDD test (`SCENARIO`/`GIVEN`/`WHEN`/`THEN`) that captures the **Acceptance criterion** before changing production code.
   - Make the minimal production change that satisfies the criterion.
   - Run the new test with a tag filter: `.\build-wsl\tests\merovingian-unit-tests "[<tag>]"`.
   - Run the full suite with `python build.py wsl` and read `build-wsl/meson-logs/testlog.txt` for the `Ok:`/`Fail:`/`Timeout:` summary.
   - Update `CHANGELOG.md` and the relevant docs (see `docs/CLAUDE.md`).
3. Follow the project rules: RAII, no raw pointers, `std::ignore` not `(void)`, `core::SecretBuffer` for secrets, fail-closed defaults, and Matrix v1.19 conformance.
4. If a finding is unclear or the cited code has changed, stop and ask for clarification rather than assume.

---

## Executive summary

- **Confirmed findings:** 25 (15 High, 8 Medium, 1 Low)
- **Refuted findings:** 1
- **Coverage gaps:** 14 areas not fully audited

The highest-risk cluster is the **server signing-secret lifecycle** (findings 1–7, 16–17, 20): plaintext fallback, repeated master-key re-derivation, and Ed25519 seed material stored in plain `std::array` instead of `core::SecretBuffer`. The next highest-risk cluster is **unbounded memory growth** (findings 11–13, 19) reachable from federation EDUs, the ThreadPool queue, and media repository vectors.

---

## Findings

### 1. Plaintext server signing-secret fallback when master key is absent
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/room_service.cpp`
- **Line range:** `2008–2024`
- **Related files:** `src/homeserver/room_service.cpp:310–330`, `src/homeserver/room_service.cpp:1813–1858`, `include/merovingian/database/persistent_store.hpp:78`, `src/crypto/master_key.cpp`
- **Description:** `encrypt_signing_secret()` returns `std::nullopt` when no master key is configured. The caller then stores the Ed25519 seed as base64 plaintext in `server_signing_keys.secret_key` with `encrypted='false'`.
- **Root cause:** Missing fail-closed guard at the point of key generation/persistence.
- **Impact:** A database exfiltration attacker obtains a server signing secret capable of forging federation PDUs and server-server requests.
- **Recommended fix:** Refuse to persist a new server signing secret unless a master key is configured. Treat a missing master key as a hard error during key generation, and never write `encrypted='false'` signing-secret rows.
- **Acceptance criterion:**
  - GIVEN the server has no master key configured
  - WHEN it attempts to generate or persist a new server signing secret
  - THEN the operation fails and no plaintext `secret_key` row is written.
- **Spec/rule reference:** Project security rules: secrets must be encrypted at rest; `core::SecretBuffer` for key material. See `docs/crypto-boundary.md`, `docs/security-coding-rules.md`.

---

### 2. Master-key mlock failure is warn-only, not fail-closed
- **Severity:** High
- **Priority:** P0
- **File:** `src/crypto/master_key.cpp`
- **Line range:** `80–93`
- **Related files:** `include/merovingian/core/secret_buffer.hpp`, `src/platform/runtime_hardening.cpp`
- **Description:** `load_master_key_material()` tolerates a failed `sodium_mlock()` and returns the root secret in ordinary swappable memory after logging a one-time warning.
- **Root cause:** `mlock` failure is treated as non-fatal.
- **Impact:** `RLIMIT_MEMLOCK` exhaustion silently downgrades the master key store, allowing the root secret to be swapped or present in core dumps.
- **Recommended fix:** Return `std::nullopt` or abort when the master-key `SecretBuffer` cannot be locked. Do not continue startup with an unlocked master key.
- **Acceptance criterion:**
  - GIVEN `sodium_mlock()` fails for the master-key buffer
  - WHEN `load_master_key_material()` is called
  - THEN it returns `std::nullopt` and the caller reports a fatal error.
- **Spec/rule reference:** Project security rules: fail-closed for crypto boundary; RAII for `SecretBuffer`.

---

### 3. Signing-secret encryption/decryption re-reads the master key per call
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/room_service.cpp`
- **Line range:** `310–330`, `1813–1858`
- **Related files:** `src/crypto/master_key.cpp`, `src/crypto/secret_box.cpp`, `src/homeserver/runtime.cpp`
- **Description:** `encrypt_signing_secret()` and `decrypt_stored_signing_secret()` load the master key file and re-derive the secret-box key on every call. The token-HMAC cache avoids this for access tokens, but the signing-secret path does not.
- **Root cause:** No derived-key cache for the signing-secret path.
- **Impact:** Re-materialises the root secret and re-exhausts `RLIMIT_MEMLOCK`, increasing exposure window and risk of mlock failure.
- **Recommended fix:** Cache the derived `SecretBoxKey` against the master-key file identity (e.g. file path + hash) so the file is read only when the identity changes. Clear the cache when the identity changes.
- **Acceptance criterion:**
  - GIVEN the same master key file is used across multiple signing-secret encrypt/decrypt operations
  - WHEN the second operation runs
  - THEN the master key file is not read again and the cached derived key is reused.
- **Spec/rule reference:** Project security rules: minimise root-secret exposure; `docs/crypto-boundary.md`.

---

### 4. Runtime signing provider holds secrets in unmlocked `std::array`
- **Severity:** High
- **Priority:** P0
- **File:** `include/merovingian/crypto/runtime_multikey_ed25519_provider.hpp`
- **Line range:** `24–31`
- **Related files:** `src/crypto/runtime_multikey_ed25519_provider.cpp`, `src/homeserver/runtime.cpp:282–310`
- **Description:** `RuntimeMultiKeyEd25519Provider` stores Ed25519 signing secrets in `std::unordered_map<std::string, std::array<unsigned char, 64U>>`.
- **Root cause:** `std::array` is neither mlocked nor zeroised.
- **Impact:** Forgery-capable Ed25519 seed material lives in ordinary process memory for the process lifetime and may be swapped or leaked via core dumps.
- **Recommended fix:** Store provider signing secrets in `core::SecretBuffer`. Update the provider interface to accept/borrow `SecretBuffer` bytes, and zeroise on destruction/replacement.
- **Acceptance criterion:**
  - GIVEN a signing provider is populated with active keys
  - WHEN its memory is inspected
  - THEN the Ed25519 seeds are held in mlocked `SecretBuffer` regions, not plain heap `std::array`s.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for all key material; no raw pointers.

---

### 5. Intermediate `std::array` copies when populating signing provider
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/runtime.cpp`
- **Line range:** `282–310`
- **Related files:** `include/merovingian/crypto/runtime_multikey_ed25519_provider.hpp`, `src/crypto/runtime_multikey_ed25519_provider.cpp`
- **Description:** `rebuild_signing_provider()` copies active signing secrets from `SecretBuffer` into a `std::vector<std::pair<std::string, std::array<unsigned char, 64U>>>` before handing them to the provider.
- **Root cause:** Intermediate container is a plain `std::array` and is destroyed without zeroisation.
- **Impact:** Duplicates the signing secret in unprotected memory during provider rebuild.
- **Recommended fix:** Avoid the intermediate vector and construct the provider directly from `SecretBuffer`-held secrets, or wipe intermediate copies immediately after transfer.
- **Acceptance criterion:**
  - GIVEN `rebuild_signing_provider()` runs
  - WHEN the temporary vector goes out of scope
  - THEN no copy of the Ed25519 seed remains in unprotected memory.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material; RAII for cleanup.

---

### 6. Production signing providers store secrets in plain `std::array`, not `SecretBuffer`
- **Severity:** High
- **Priority:** P0
- **File:** `src/crypto/runtime_multikey_ed25519_provider.cpp`
- **Line range:** `15–20`
- **Related files:** `include/merovingian/crypto/runtime_multikey_ed25519_provider.hpp`, `src/homeserver/runtime.cpp:282–310`
- **Description:** Both `RuntimeEd25519Provider` and `RuntimeMultiKeyEd25519Provider` hold 64-byte Ed25519 signing secrets in plain `std::array`. `reset_runtime_crypto_provider` copies secrets out of `core::SecretBuffer` into these arrays.
- **Root cause:** Provider data model uses `std::array`.
- **Impact:** Duplicates the secret in an unprotected container for the lifetime of the provider.
- **Recommended fix:** Convert the providers to store signing secrets in `core::SecretBuffer` and zeroise any temporary copies.
- **Acceptance criterion:**
  - GIVEN the runtime crypto provider is reset with active signing keys
  - WHEN the provider is destroyed or replaced
  - THEN the old provider's key memory is zeroised and was mlocked.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material.

---

### 7. `generate_ed25519_keypair` returns the secret key in a plain `std::array`
- **Severity:** High
- **Priority:** P0
- **File:** `src/crypto/ed25519.cpp`
- **Line range:** `53–66`
- **Related files:** `include/merovingian/crypto/ed25519.hpp`, `src/homeserver/room_service.cpp:2008–2024`
- **Description:** `Ed25519Keypair.secret_key` is declared as `std::array<std::uint8_t, 64U>`, and `generate_ed25519_keypair` returns the struct by value. Callers keep the generated signing secret in this transient plain array while encoding it for storage.
- **Root cause:** Key generation API returns secrets in a non-secure container.
- **Impact:** Generated signing secret exists in unzeroised ordinary memory from generation through storage encoding.
- **Recommended fix:** Return the generated secret in a `core::SecretBuffer`, or zeroise the `Ed25519Keypair` before it goes out of scope. Update the public API to use `SecretBuffer`.
- **Acceptance criterion:**
  - GIVEN a new Ed25519 keypair is generated
  - WHEN the keypair object goes out of scope
  - THEN the secret seed bytes are zeroised and no copy remains in ordinary memory.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material.

---

### 8. Federation media download hardcodes `Content-Disposition: inline`
- **Severity:** High
- **Priority:** P0
- **File:** `src/media/repository.cpp`
- **Line range:** `570–571`
- **Related files:** `include/merovingian/media/repository.hpp`, `docs/media-repository.md`
- **Description:** `build_federation_media_download_body()` unconditionally emits `Content-Disposition: inline` for the media part, regardless of actual content type.
- **Root cause:** Hardcoded disposition string.
- **Impact:** Non-inline-safe content types (e.g. executables, HTML with scripts) are delivered with `inline`, telling receiving homeservers' clients to render them inline and bypassing the local disposition allow-list.
- **Recommended fix:** Derive `Content-Disposition` from the MIME allow-list/quarantine decision. Default to `attachment` for unknown or non-inline-safe types. Add spec-conformance tests for non-inline-safe types.
- **Acceptance criterion:**
  - GIVEN a federation media download for a non-inline-safe MIME type (e.g. `application/x-msdownload`)
  - WHEN the response is built
  - THEN `Content-Disposition` is `attachment`, not `inline`.
- **Spec/rule reference:** Matrix v1.19 media repository semantics; project security rules: fail-closed for content disposition.

---

### 9. Thumbnail worker sandbox is Linux-only
- **Severity:** High
- **Priority:** P0
- **File:** `src/media/thumbnail_worker_main.cpp`
- **Line range:** `91–122`
- **Related files:** `src/platform/runtime_hardening.cpp`, `src/platform/hardening_self_check.cpp`, `docs/hardening.md`
- **Description:** `harden()` applies seccomp-bpf only on `__linux__`; on FreeBSD and NetBSD the worker relies solely on `setrlimit`. `sandboxed_worker_plan_is_hardened()` only validates boolean plan flags, not that restrictions succeeded.
- **Root cause:** Platform-specific sandbox code not implemented for BSDs; plan check is declarative, not runtime-probed.
- **Impact:** Thumbnail worker on documented Tier 1 BSD support has minimal sandboxing, increasing blast radius from image-decoder bugs.
- **Recommended fix:** Apply platform-appropriate sandbox primitives on every supported platform (Capsicum on FreeBSD, pledge on NetBSD/OpenBSD). Make the plan check verify the restrictions are active and fail closed if not.
- **Acceptance criterion:**
  - GIVEN the thumbnail worker starts on FreeBSD or NetBSD
  - WHEN `harden()` completes
  - THEN the process is restricted by the platform sandbox primitive, and the self-check reports enabled.
- **Spec/rule reference:** Project security rules: sandbox untrusted parsers; `docs/platform-support.md` for Tier 1 BSD support.

---

### 10. Startup hardening self-check blocks documented Tier 1 BSD support
- **Severity:** High
- **Priority:** P0
- **File:** `src/platform/hardening_self_check.cpp`
- **Line range:** `247–249`
- **Related files:** `src/main.cpp`, `src/platform/runtime_hardening.cpp`, `tests/unit/test_hardening_self_check.cpp`
- **Description:** On non-Linux platforms the self-check reports core-dump policy, `no_new_privs`, and capability bounding as `HardeningStatus::unknown`. `is_ready()` returns false when any check is not enabled, and `src/main.cpp` aborts startup.
- **Root cause:** Linux-only controls are treated as unknown rather than not-applicable or implemented via BSD equivalents.
- **Impact:** Production startup fails on FreeBSD/OpenBSD despite documented Tier 1 support.
- **Recommended fix:** Align the self-check with the documented BSD support matrix: report Linux-only controls as enabled-not-applicable or implement BSD equivalents. Update `tests/unit/test_hardening_self_check.cpp` accordingly.
- **Acceptance criterion:**
  - GIVEN the server is started on a documented Tier 1 BSD platform with all available hardening applied
  - WHEN the self-check runs
  - THEN `is_ready()` returns true and the server starts.
- **Spec/rule reference:** `docs/platform-support.md`; project security rules: hardening gates must not break supported platforms.

---

### 11. Unbounded `ThreadPool` work queue
- **Severity:** High
- **Priority:** P0
- **File:** `src/net/thread_pool.cpp`
- **Line range:** `105–120`
- **Related files:** `src/net/acceptor.cpp`, `src/net/tls_acceptor.cpp`, `include/merovingian/net/thread_pool.hpp`
- **Description:** `ThreadPool::submit()` appends closures to a `std::queue` without any size cap. Both plain-HTTP and TLS accept loops submit one closure per accepted connection.
- **Root cause:** Unbounded queue with no backpressure.
- **Impact:** A connection flood grows the queue without bound, leading to OOM and denial of service.
- **Recommended fix:** Add a configurable maximum queue depth. Return false and close the connection when the cap is reached.
- **Acceptance criterion:**
  - GIVEN the thread pool queue is at its configured maximum depth
  - WHEN a new connection attempts to submit work
  - THEN the submit returns false and the connection is closed without queuing.
- **Spec/rule reference:** Project security rules: bound all resources reachable from network input.

---

### 12. Unbounded in-memory `typing_users` vector from federation typing EDUs
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/local_http_router.cpp`
- **Line range:** `986`
- **Related files:** `include/merovingian/homeserver/runtime.hpp`, `src/homeserver/runtime.cpp`
- **Description:** `HomeserverRuntime::typing_users` only shrinks when a previously-seen user sends `typing=false`. A malicious federated server can send `typing=true` EDUs for arbitrarily many distinct `user_id`/`room_id` pairs.
- **Root cause:** No upper bound or eviction on the typing state vector.
- **Impact:** Monotonic memory growth from federation input, leading to OOM.
- **Recommended fix:** Cap the stored typing entries and evict oldest/least-recently-used when the cap is exceeded. Validate room membership before storing state.
- **Acceptance criterion:**
  - GIVEN the typing_users vector is at its cap
  - WHEN a new federation typing=true EDU arrives for a different room/user
  - THEN the oldest entry is evicted and memory usage stays bounded.
- **Spec/rule reference:** Project security rules: bound all resources from federation input; Matrix v1.19 federation EDUs.

---

### 13. Unbounded in-memory `receipts` vector from federation receipt EDUs
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/local_http_router.cpp`
- **Line range:** `1069`
- **Related files:** `include/merovingian/homeserver/runtime.hpp`, `src/homeserver/runtime.cpp`
- **Description:** `HomeserverRuntime::receipts` is upserted but never reaped. A malicious federated server can create unbounded distinct receipts by varying `room_id`s and synthetic `user_id`s.
- **Root cause:** No upper bound or eviction on the receipts vector.
- **Impact:** Monotonic memory growth from federation input, leading to OOM.
- **Recommended fix:** Bound the receipts vector and evict oldest/least-recently-used entries. Reject receipt EDUs for rooms where the sender has no state.
- **Acceptance criterion:**
  - GIVEN the receipts vector is at its cap
  - WHEN a new federation receipt EDU arrives for a different room/user
  - THEN the oldest entry is evicted and memory usage stays bounded.
- **Spec/rule reference:** Project security rules: bound all resources from federation input; Matrix v1.19 federation EDUs.

---

### 14. Exception-unsafe manual `runtime.mutex` release
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/client_server.cpp`
- **Line range:** `11003–11204`
- **Related files:** `src/homeserver/local_http_router.cpp` (for `NetworkIoUnlock`/`ScopedGuardRelease` helpers), `include/merovingian/homeserver/runtime.hpp`
- **Description:** Multiple endpoints perform `guard.unlock()` before a blocking outbound call and `guard.lock()` after it. If the outbound call throws between unlock and lock, the mutex is left unlocked, serialising every client request and inbound federation transaction.
- **Root cause:** Manual lock/unlock instead of RAII scope guard.
- **Impact:** A thrown exception can leave the global runtime mutex unlocked, causing global serialization or deadlock.
- **Recommended fix:** Replace every manual `guard.unlock()/guard.lock()` pair around outbound calls with a RAII scope (`NetworkIoUnlock`/`ScopedGuardRelease`) so the mutex is always restored on both normal and exceptional paths.
- **Acceptance criterion:**
  - GIVEN an endpoint that releases the runtime mutex for an outbound call
  - WHEN the outbound call throws
  - THEN the mutex is re-locked exactly once before the exception propagates.
- **Spec/rule reference:** Project rules: RAII is non-negotiable; prefer references over pointers; no manual new/delete.

---

### 15. SSO `redirectUrl` allowlist prefix match bypasses subdomains
- **Severity:** High
- **Priority:** P0
- **File:** `src/homeserver/auth_service.cpp`
- **Line range:** `384–393`
- **Related files:** `src/homeserver/client_server.cpp` (SSO endpoints), `docs/auth-identity.md`
- **Description:** `redirect_url_is_allowed()` returns true when `redirect_url.starts_with(allowed)` without enforcing a path or origin boundary. An allowlist entry such as `https://example.com` matches `https://example.com.evil.com/callback`.
- **Root cause:** Prefix match treated as origin match.
- **Impact:** An attacker can receive a freshly minted `loginToken` by hosting a subdomain or path-prefix that starts with the allowed URL.
- **Recommended fix:** After a prefix match, require the next character to be `/`, `?`, `#`, or end-of-string, or parse and compare origins exactly. Add tests for subdomain and path-prefix bypasses.
- **Acceptance criterion:**
  - GIVEN `https://example.com` is the only allowed redirect URL
  - WHEN `https://example.com.evil.com/callback` is checked
  - THEN it is rejected.
- **Spec/rule reference:** Matrix v1.19 SSO / login-token semantics; project security rules: fail-closed on auth decisions.

---

### 16. Decrypted signing secret passes through unprotected `std::vector`
- **Severity:** Medium
- **Priority:** P0
- **File:** `src/crypto/secret_box.cpp`
- **Line range:** `108–129`
- **Related files:** `include/merovingian/core/secret_buffer.hpp`, `src/homeserver/room_service.cpp:1813–1858`
- **Description:** `secret_box_decrypt()` returns decrypted plaintext as `std::optional<std::vector<std::uint8_t>>` rather than `SecretBuffer`. Callers copy the result into `SecretBuffer`, but the intermediate vector is freed without zeroisation.
- **Root cause:** Decryption API returns a plain container.
- **Impact:** Decrypted signing secret briefly exists in unprotected heap memory.
- **Recommended fix:** Return `SecretBuffer` from `secret_box_decrypt` so the decrypted signing secret is mlocked and zeroised for its entire lifetime.
- **Acceptance criterion:**
  - GIVEN `secret_box_decrypt()` succeeds
  - WHEN the caller receives the plaintext
  - THEN it is already in a `core::SecretBuffer` and no intermediate `std::vector` copy exists.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material.

---

### 17. Persistent signing-secret row uses `std::string`, not `SecretBuffer`
- **Severity:** Medium
- **Priority:** P0
- **File:** `include/merovingian/database/persistent_store.hpp`
- **Line range:** `78`
- **Related files:** `src/database/persistent_store.cpp`, `src/homeserver/room_service.cpp:2008–2024`
- **Description:** `PersistentServerSigningKey.secret_key` is a `std::string`. The in-memory persistent store therefore holds encrypted (and, for legacy rows, plaintext) signing-secret material in unpinned, unzeroised heap memory.
- **Root cause:** Persistent store struct uses `std::string` for secret material.
- **Impact:** Signing-secret material (encrypted or legacy plaintext) is not protected by `SecretBuffer` guarantees.
- **Recommended fix:** Use `core::SecretBuffer` for the `secret_key` field, or at minimum zeroise the string when the struct is destroyed/moved.
- **Acceptance criterion:**
  - GIVEN a `PersistentServerSigningKey` is loaded
  - WHEN the struct is destroyed
  - THEN the `secret_key` bytes are zeroised and the memory was mlocked.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material.

---

### 18. PostgreSQL migrations run as login role
- **Severity:** Medium
- **Priority:** P1
- **File:** `src/database/postgresql_store.cpp`
- **Line range:** `1426–1455`
- **Related files:** `docs/database-persistence.md`, `migrations/AGENTS.md`
- **Description:** `open_postgresql_persistent_store()` applies pending migrations as the PostgreSQL login role, not the configured migration role, before switching to the runtime role. The comment states this is required because `ALTER TABLE` needs table ownership.
- **Root cause:** Runtime process performs DDL with an elevated role.
- **Impact:** Privilege-separation design is bypassed during migrations.
- **Recommended fix:** Make `migration_role` own the schema objects (or use a separate offline migrator) so the runtime connection runs exclusively as the DML-only runtime role.
- **Acceptance criterion:**
  - GIVEN a migration is pending
  - WHEN the runtime process opens the PostgreSQL store
  - THEN DDL is executed only as the configured migration role, not the login or runtime role.
- **Spec/rule reference:** Project security rules: privilege separation; `docs/database-persistence.md`.

---

### 19. Unbounded media repository growth
- **Severity:** Medium
- **Priority:** P0
- **File:** `src/media/repository.cpp`
- **Line range:** `432`
- **Related files:** `include/merovingian/media/repository.hpp`, `src/media/repository.cpp:570–571`
- **Description:** `upload_local_media()` pushes every accepted blob into an in-memory `std::vector<LocalMediaBlob>`, and `fetch_remote_media()` reuses the same path. There is no cap on total records, total bytes, per-user quotas, or cache eviction.
- **Root cause:** In-memory media index is unbounded and fully restored on startup.
- **Impact:** OOM from upload spam or large remote media caches; slow startup from full restore.
- **Recommended fix:** Add repository-wide and per-origin caps (total records, total bytes, per-user quotas) before accepting or caching a new blob. Reject or evict oldest entries when the cap is reached.
- **Acceptance criterion:**
  - GIVEN the media repository is at its configured cap
  - WHEN a new upload or remote fetch is attempted
  - THEN the operation is rejected or the oldest entry is evicted, and memory stays bounded.
- **Spec/rule reference:** Project security rules: bound all resources reachable from network input; Matrix v1.19 media repository.

---

### 20. Master key loader retains plaintext bytes in `std::ifstream` buffer
- **Severity:** Medium
- **Priority:** P1
- **File:** `src/crypto/master_key.cpp`
- **Line range:** `28`
- **Related files:** `include/merovingian/core/secret_buffer.hpp`
- **Description:** `load_master_key_material()` reads the master-key file through `std::ifstream`. The stream's internal `std::filebuf` buffer holds plaintext master-key bytes and is freed without zeroisation.
- **Root cause:** Stream buffering.
- **Impact:** Plaintext master-key bytes may remain in ordinary heap memory after the read.
- **Recommended fix:** Disable stream buffering or read with a low-level unbuffered API directly into the `SecretBuffer`, and wipe the read buffer after each chunk.
- **Acceptance criterion:**
  - GIVEN the master key file is loaded
  - WHEN the load completes
  - THEN no plaintext master-key bytes remain in `std::ifstream` internal buffers.
- **Spec/rule reference:** Project security rules: `core::SecretBuffer` for key material; minimise plaintext exposure.

---

### 21. Core-dump policy ignores `prctl(PR_SET_DUMPABLE, 0)` failure
- **Severity:** Medium
- **Priority:** P1
- **File:** `src/platform/runtime_hardening.cpp`
- **Line range:** `381`
- **Related files:** `src/platform/hardening_self_check.cpp`, `src/platform/runtime_hardening.cpp`
- **Description:** `apply_linux_core_dump_policy()` returns success whenever `setrlimit(RLIMIT_CORE)` succeeds, regardless of whether `prctl(PR_SET_DUMPABLE, 0, ...)` succeeded. The matching self-check only verifies `RLIMIT_CORE` limits, not `PR_GET_DUMPABLE`.
- **Root cause:** Function does not check `prctl` return value; self-check does not probe dumpable flag.
- **Impact:** Core dumps may still be produced even when the policy reports success.
- **Recommended fix:** Make the function return false if `prctl(PR_SET_DUMPABLE, 0, ...)` fails, and extend the self-check to verify the dumpable flag with `prctl(PR_GET_DUMPABLE)`.
- **Acceptance criterion:**
  - GIVEN `prctl(PR_SET_DUMPABLE, 0, ...)` fails
  - WHEN `apply_linux_core_dump_policy()` is called
  - THEN it returns false and startup fails closed.
- **Spec/rule reference:** Project security rules: fail-closed for hardening; `docs/hardening.md`.

---

### 22. `is_secure_secret_file()` permits owner-write
- **Severity:** Medium
- **Priority:** P1
- **File:** `src/platform/file_metadata.cpp`
- **Line range:** `81–86`
- **Related files:** `tests/unit/test_file_metadata.cpp`, `docs/security-coding-rules.md`
- **Description:** `is_secure_secret_file()` validates regular files, no group/other permissions, and no execute bits, but does not reject `owner_write`.
- **Root cause:** Missing owner-write check.
- **Impact:** Secret files can be writable by their owner, contrary to the documented owner-read-only rule.
- **Recommended fix:** Add `!metadata.mode.owner_write` to the check and add/update unit tests in `tests/unit/test_file_metadata.cpp`.
- **Acceptance criterion:**
  - GIVEN a secret file with owner-write permission (e.g. `0600`)
  - WHEN `is_secure_secret_file()` is called
  - THEN it returns false.
- **Spec/rule reference:** `docs/security-coding-rules.md`; project security rules: secret files must be owner-read-only.

---

### 23. `server.server_name` not validated against Matrix grammar
- **Severity:** Medium
- **Priority:** P1
- **File:** `src/config/config.cpp`
- **Line range:** `546–549`
- **Related files:** `include/merovingian/config/config.hpp`, `docs/matrix-v1.19-spec/appendices.md#identifier-grammar`
- **Description:** `config::validate()` only checks that `server.server_name` is non-empty. It accepts malformed values such as `:8000` or `example..com`.
- **Root cause:** Missing grammar validation.
- **Impact:** Malformed server names reach runtime and are used to construct user IDs and federation routing keys.
- **Recommended fix:** Validate `server.server_name` against the Matrix v1.19 `server_name` grammar in `config::validate()`.
- **Acceptance criterion:**
  - GIVEN a config with `server.server_name = ":8000"`
  - WHEN `config::validate()` runs
  - THEN validation fails with a clear error.
- **Spec/rule reference:** Matrix v1.19 appendices, Identifier Grammar, `server_name`.

---

### 24. Malformed token expiry parsed as 'never expires'
- **Severity:** Low
- **Priority:** P1
- **File:** `src/database/persistent_store.cpp`
- **Line range:** `345–359`
- **Related files:** `src/auth/token_lifecycle.cpp`, `tests/unit/test_persistent_store.cpp`
- **Description:** `parse_expires_at()` treats any malformed `expires_at` TEXT value as `std::nullopt` rather than rejecting the token.
- **Root cause:** Fail-open parsing.
- **Impact:** A corrupt or attacker-modified row becomes a non-expiring credential.
- **Recommended fix:** Treat a malformed `expires_at` as an invalid/expired token (fail closed) rather than defaulting to no expiry.
- **Acceptance criterion:**
  - GIVEN a token row with a malformed `expires_at` value
  - WHEN the token is loaded
  - THEN it is treated as expired/invalid and cannot be used.
- **Spec/rule reference:** Project security rules: fail-closed on auth decisions.

---

## Refuted findings

### R1. Manual parsing of `to_device` extension sync token
- **File:** `src/sync/sliding_sync_extensions.cpp:90`
- **Ruling:** Not a server-wide security issue.
- **Reason:** The `extensions.to_device.since` field is an extension-specific position token, not a top-level `/sync` `next_batch` token. The top-level sliding-sync `pos` token is correctly decoded via `sync::decode_stream_token`, and the top-level `next_batch` is encoded via `sync::encode_stream_token`. The malformed-input risk is self-targeting.
- **Action:** No code change required. Do not add a finding for this location.

---

## Coverage gaps (not audited)

The implementing LLM should be aware that the following areas were **not** covered by this audit and may contain additional issues:

1. **Auth and identity:** UIAA stages, password hashing, refresh/access token lifecycle, device management, SSO token exchange.
2. **Federation inbound PDU verification:** signature verification, auth event checks, state resolution, backfill, rate-limit handling.
3. **Event authorization and room versions:** auth rules, power-level evaluation, redaction, reference/content hash verification, room-version policy.
4. **End-to-end encryption:** device keys, Olm/Megolm, key backup, secret storage, cross-signing, fallback keys.
5. **Rate limiting and circuit breakers:** per-endpoint, per-user, and federation rate-limit implementations and bypasses.
6. **HTTP/TLS transport:** header parsing, request body limits, keep-alive idle parking, TLS handshake errors, HSTS/certificate validation.
7. **Application Service and Push Gateway APIs:** AS token auth, transaction handling, push gateway request signing.
8. **IPC and federation worker:** AEAD key exchange, supervisor boundary, proxy routing security.
9. **Content scanner and trust & safety:** MIME allow-list, quarantine, media metadata extraction, policy engine.
10. **Configuration beyond `server.server_name`:** listeners, database roles, logging, media limits, federation allow/deny lists.
11. **Observability and audit logging:** secret redaction, audit-event access, log injection.
12. **SQL construction paths:** all SQL construction, especially dynamic identifiers and federation queries.
13. **Privilege separation runtime enforcement:** PostgreSQL runtime role always-set check; SQLite reduced-privilege check.
14. **Bootstrap and migration ordering:** migration numbering, rollback safety, idempotency.

---

## Suggested work order for the implementing LLM

### Phase 1 — Signing-secret lifecycle (findings 1–7, 16–17, 20)
These are the highest-impact fixes. They touch `core::SecretBuffer`, `crypto::ed25519`, `crypto::secret_box`, `crypto::master_key`, `crypto::runtime_multikey_ed25519_provider`, `homeserver::runtime`, `homeserver::room_service`, and `database::persistent_store`.

1. Convert `Ed25519Keypair.secret_key` and provider maps to `core::SecretBuffer`.
2. Return `SecretBuffer` from `secret_box_decrypt` and `generate_ed25519_keypair`.
3. Remove plaintext signing-secret fallback; require master key for new secrets.
4. Cache derived `SecretBoxKey` for signing-secret encrypt/decrypt.
5. Convert `PersistentServerSigningKey.secret_key` to `SecretBuffer`.
6. Eliminate intermediate `std::array`/`std::vector` copies during provider population.
7. Make master-key `mlock` failure fail-closed and fix `std::ifstream` buffering.

### Phase 2 — Unbounded resource growth (findings 11–13, 19)
1. Cap `ThreadPool` work queue with backpressure.
2. Cap `typing_users` and `receipts` with LRU eviction and membership validation.
3. Cap media repository (total records, total bytes, per-user quotas) and restore lazily or with limits.

### Phase 3 — High-severity correctness fixes (findings 8, 10, 14, 15)
1. Fix federation media `Content-Disposition` to derive from MIME allow-list.
2. Fix exception-unsafe `runtime.mutex` handling with RAII scope guards.
3. Fix SSO `redirectUrl` prefix match to enforce origin/path boundaries.
4. Align BSD hardening self-check with documented Tier 1 support.

### Phase 4 — Medium-severity hardening (findings 18, 21–23)
1. Run PostgreSQL migrations under a dedicated migration role.
2. Fail closed on `prctl(PR_SET_DUMPABLE, 0)` failure and probe `PR_GET_DUMPABLE`.
3. Reject owner-write in `is_secure_secret_file()`.
4. Validate `server.server_name` against Matrix v1.19 grammar.

### Phase 5 — Low-severity correctness (finding 24)
1. Treat malformed `expires_at` as expired/invalid.

### Phase 6 — Documentation and verification
1. Update `docs/threat-model.md`, `docs/crypto-boundary.md`, `docs/security-coding-rules.md`, `docs/hardening.md`, `docs/database-persistence.md`, and `CHANGELOG.md`.
2. Run `python build.py wsl`, read `build-wsl/meson-logs/testlog.txt` for `Ok:`/`Fail:`/`Timeout:` counts.
3. Run affected Catch2 binaries with tag filters (e.g. `.\build-wsl\tests\merovingian-unit-tests "[security]"`).

---

## Version bump and changelog

Per `docs/versioning.md`, this branch targets `0.12.5`. The `CHANGELOG.md` entry should be added at branch creation and all version locations updated immediately before the PR:

- `meson.build`
- `src/main.cpp`
- `src/db_migrate.cpp`
- `packaging/freebsd/+MANIFEST`
- `packaging/netbsd/Makefile`
- `packaging/rpm/merovingian.spec` (+ `%changelog`)
- `packaging/rhel/merovingian.spec` (+ `%changelog`)
- `packaging/opensuse/merovingian.spec` (+ `%changelog`)
- `scripts/build-deb.sh`
- `scripts/build-rpm.sh`
- `scripts/build-rhel-rpm.sh`
- `scripts/build-opensuse-rpm.sh`
- `scripts/build-freebsd-pkg.sh`
- `scripts/build-netbsd-pkg.sh`
- `scripts/build-openbsd-pkg.sh`
- `scripts/build-static-linux.sh`
- `CHANGELOG.md`

Run `tests/tooling/test_packages_workflow.py` (or `python build.py wsl`) after bumping to catch missed locations.
