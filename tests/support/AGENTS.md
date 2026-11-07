# tests/support/ — Test Support Helpers

Shared test utilities used across unit, conformance, and integration tests.

## Contents

| File | Purpose |
|---|---|
| `appservice_test_config.hpp` | `TestAppservice` and `appservice_test_config()`: write registration files for appservices with the as_token `as-token-<id>`, hs_token `hs-token-<id>` and sender `_<id>_bot`, and build a `Config` that loads them (token registration on, in-memory database). Adjust the returned `Config` (for example `appservice().max_queued_events`) before starting the runtime |
| `MockAppservice.hpp` | `MockAppservice`: a loopback plain-HTTP appservice that records every request (method, target, `Authorization`, body), answers with a settable global status or per-target-prefix answers, and can `go_silent()` to make the homeserver's outbound timeout fire. Like `tls_mock_server.hpp` it breaks the no-I/O rule because conformance and integration suites share it |
| `JoiningThreads.hpp` | `JoiningThreads`: a set of `std::thread`s all joined on scope exit, or earlier with `join()` when a scenario asserts on what the threads did. Use it instead of `std::jthread`, which the libc++ on FreeBSD and OpenBSD does not provide |
| `catch_report_arguments.hpp` | `catch_report_arguments()`: the command line a `test_main.cpp` hands to Catch2, plus an XML reporter writing `<dir>/<binary>-<pid>.xml` when `MEROVINGIAN_CATCH_REPORT_DIR` is set (unchanged otherwise); read by `scripts/check_expected_skips.py` (ADR-0546) |
| `NonCapturingXmlReporter.hpp` | `NonCapturingXmlReporter`, registered as `merovingian-xml` by each `test_main.cpp`: Catch2's XML reporter without stdout capture, which `catch_report_arguments()` asks for. The stock one redirects stdout and breaks tests that swap `std::cout.rdbuf()` (ADR-0546) |
| `json_test_support.hpp` | JSON assertion helpers: `require_json_key()`, `parse_or_fail()` |
| `master_key.hpp` | `master_key_file()` writes a unique random 256-bit master key file (mode 0400) to the temp directory; `shared_master_key_file()` returns one such file per test process, so a restarted runtime can decrypt what the first run stored. Test-only; it writes a file, so it is an I/O exception |
| `RealPasswordHashCost.hpp` / `.cpp` | The minimum-cost `crypto_pwhash_str` the unit, conformance and integration binaries link through `--wrap` (ADR-0510), and `RealPasswordHashCost`, the guard for a scenario that races another request against the Argon2id window |
| `process_tasks.hpp` | `count_process_tasks()`: number of threads in this process from `/proc/self/task`; used by the no-thread-before-hardening scenarios (ISO-1) |
| `state_group_scan.hpp` | `state_group_index_mismatch()`: compares the store's indexed state-group lookups with a linear scan of the rows (empty string when they agree); `scanned_*` give the scan answers. Used after writes, hydration and reload (ADR-0325) |
| `room_history_fixture.hpp` | `record_joined_state_for_room()`: for a fixture that writes events straight into a `PersistentStore`, records one state group in which a user is joined and maps the room's events to it, so the history-visibility filter (CSAZ-3) lets that user read them |
| `ingested_state_fixture.hpp` | `record_ingested_state()` / `record_ingested_state_for_room()`: for a fixture that writes events straight into a `PersistentStore` and then asks for the state AT an event (federation `/state`, `/state_ids`, client `/context`), records the state group ingestion would have recorded for each event (state before = resolution of the prev_events' states, state after = that plus the event, unchanged for a rejected one). Those reads answer from the recorded state, never from a walk of the event graph (ADR-0363). Call it parents first |
| `cross_signing_fixture.hpp` | `make_cross_signing_set()`: a master, self-signing and user-signing key with real Ed25519 keys and real signatures (the self-signing and user-signing keys signed by the master key), plus `sign_cross_signing_key_json()`, `cross_signing_upload_body()` and `fresh_cross_signing_upload_body()`. `POST /keys/device_signing/upload` verifies those signatures (ADR-0421), so a test that uploads cross-signing keys uses this, never invented key or signature text |
| `forged_unsigned.hpp` | `with_forged_unsigned()` / `forged_unsigned_json`: a signed PDU with the `unsigned` a hostile relaying server would write (`m.relations`, `redacted_because`, `prev_content`, `age`, `transaction_id`, `membership`). The signatures and event ID still hold, so it ingests like the genuine PDU (ADR-0402) |
| `registration_token.hpp` | Generates registration tokens for test users without going through the full UIAA flow |
| `FakeClamdServer.hpp` | `FakeClamdServer`: a clamd stand-in on a temporary AF_UNIX socket. Reads INSTREAM exchanges, records the streamed bytes and answers with a fixed reply (or stays silent for the timeout case). Another I/O exception, shared by the unit and integration suites (G15, ADR-0565); assert on its recorded data from the test thread only |
| `temp_directory.hpp` | Fallback-aware temporary-directory helper for test scratch files |
| `tls_mock_server.hpp` | Self-signed certificate generation plus one-shot and path-dispatching local TLS servers, for tests that need a real HTTPS peer. Also `MockIdentityServer`: a trusted loopback identity server serving any number of requests (responses chosen by request-line substring, requests captured, optional stall), with `cooperative_responses()` for tests that just need a 3PID validated and `install(runtime)` to trust it |
| `CapturedAppserviceRequest.hpp` | `CapturedAppserviceRequest`: one request recorded by `MockAppservice` (method, target, `Authorization`, body, answered status) |
| `TestAppservice.hpp` | `TestAppservice`: the fields of one appservice registration written by `appservice_test_config()` |
| `ConsoleLogCapture.hpp` | `ConsoleLogCapture`: sends the console log to a string for the scope's lifetime; safe only while the logger's asynchronous writer threads are not running (the unit test binary) |
| `CrossSigningKeyPair.hpp` | `CrossSigningKeyPair`: a cross-signing public key (unpadded base64) and its secret key |
| `CrossSigningSet.hpp` | `CrossSigningSet`: a user's master, self-signing and user-signing keys, the latter two signed by the master key |
| `EduRelayChannels.hpp` / `EduRelayContext.hpp` | `EduRelayChannels` and `make_edu_relay_channels()`: a main and a worker `IpcChannel` over a real authenticated transport, for the downstream EDU relay fixtures. Creates a `socketpair`, so it is an I/O exception |
| `in_memory_database_config.hpp` | `in_memory_database_config()`: selects the process-local database for tests that do not exercise persistence (production config parsing does not expose it) |
| `e2ee_caps_support.hpp` | `caps_config()` and a logged-in-user helper for the CSAZ-10 per-user end-to-end key and filter cap scenarios |
| `membership_fixture_support.hpp` | Helpers that build membership PDUs (send_join, send_leave, send_knock bodies) with the `auth_events` and `prev_events` a real server would send (ADR-0064 phase B2) |
| `remote_room_fixture.hpp` | A room on the local server with a joined user from `remote.example.org`; events the remote server sends are signed with a key derived from a seed |
| `third_party_invite_fixture.hpp` / `InviteRoom.hpp` | Fixtures for the third-party invite exchange tests: a runtime with two users, `InviteRoom` (a room holding an `m.room.third_party_invite`), and the identity server's signed object |
| `MockIdentityServer.hpp` | `MockIdentityServer`: a trusted loopback TLS identity server (see the `tls_mock_server.hpp` row). Opens a real socket, so it is an I/O exception |
| `SqliteInsertFault.hpp` | `SqliteInsertFault` (R02): makes every INSERT or UPDATE into one table of the server's database file fail from a second connection, until `clear()` or destruction. Opens the database file, so it is an I/O exception |
| `SqliteCloser.hpp` | `SqliteCloser`: deleter that closes a `sqlite3*` |
| `TlsTestCertificate.hpp` | `TlsTestCertificate`: RAII holder for a self-signed certificate and key written to a temp directory, removed on destruction. Writes files, so it is an I/O exception |
| `StallingTlsServerState.hpp` | `StallingTlsServerState`: atomics (`request_received`, `released`) a test uses to observe and release a stalling TLS server |
| `ScopedThreadJoin.hpp` | `ScopedThreadJoin`: joins a mock-server thread on scope exit so a failing `REQUIRE` does not call `std::terminate` |
| `EvpPkeyDeleter.hpp` / `X509Deleter.hpp` / `X509NameDeleter.hpp` / `FileDeleter.hpp` | Deleters for OpenSSL `EVP_PKEY`, `X509` and `X509_NAME` handles and for `std::FILE*`, used by the TLS mock server |

Note: `tests/federation_signing_test_support.hpp` — a deterministic Ed25519
federation-signing helper (`merovingian::federation::test`, seed-derived
keypairs for signing federation requests/PDUs against a matching remote key)
— lives at the top level of `tests/`, **not** in this directory. It is shared
across unit, conformance, and integration suites (confirmed by grep: used in
`tests/conformance/test_federation_conformance.cpp`,
`test_x_matrix_auth_parsing.cpp`, and others; `tests/integration/test_join_room_flow.cpp`
and other flow tests; and several `tests/unit/` files), so look for it there
first rather than assuming every shared helper lives under `tests/support/`.

## Rules

- **`master_key.hpp` is for tests only.** `master_key_file()` writes a random test key file to
  the temp directory. Nothing in the header stops it being linked into a non-test binary, so
  use it only from tests.
- Add helpers here only when they are used by **two or more** test files. Single-use helpers
  belong in an anonymous namespace in the test file that uses them.
- Helpers must not start a database, server, or any I/O — they are pure utilities.
  Any helper that requires I/O belongs in `tests/integration/` as a fixture class.
- **Exceptions — `tls_mock_server.hpp`, `MockAppservice.hpp`, `appservice_test_config.hpp`, and the other files the Contents table marks as I/O exceptions (`master_key.hpp`, `EduRelayContext.hpp`, `MockIdentityServer.hpp`, `SqliteInsertFault.hpp`, `TlsTestCertificate.hpp`, `FakeClamdServer.hpp`).**
  `tls_mock_server.hpp` writes a temp certificate and accepts real loopback TLS connections
  (it creates the certificate and key owner-only with `open_owner_only_for_write`, never `fopen`),
  `MockAppservice` (`MockAppservice.hpp`) accepts real loopback HTTP connections, and
  `appservice_test_config.hpp` writes registration files, so all three break the no-I/O rule.
  They live here because a `tests/integration/` fixture is not reachable from
  `tests/conformance/`, and both suites need the same mock peers and registrations. Keep the
  exceptions to these files: any new I/O helper used by only one suite still belongs in that
  suite's directory.
