# Every module file is named in PascalCase, including function-only headers

* Status: accepted; amends [ADR-0467](0467-type-filenames-match-the-type-name-exactly.md) and [ADR-0530](0530-a-header-is-renamed-after-its-type-only-when-it-is-about-that-type.md)
* Deciders: James Chapman
* Date: 2026-11-10

Technical Story: the file-naming sweep of 0.12.89

## Context and Problem Statement

ADR-0467 named a file after the one type it defines and let a header that defines no type keep a `snake_case` name.
ADR-0530 then extracted types out of mixed headers, which left 148 function-only headers and their sources in
`snake_case` beside 766 PascalCase type headers. A module directory read as two naming schemes, and the project owner
asked for one. What is a function-only file called, and what keeps a lower-case name?

## Considered Options

* Name every module header and source in PascalCase: a type's file after the type, a function-only file after the
  PascalCase form of the concept it was named for
* Keep `snake_case` for function-only files (ADR-0467 as written)
* Fold each function-only header into a type header of the same module

## Decision Outcome

Chosen option: "PascalCase for every module file".

* A file that defines a type is named after it, exactly (ADR-0467, unchanged).
* A file that defines no type takes the PascalCase form of its concept: `policy_engine.hpp` became `PolicyEngine.hpp`,
  `sqlite_store.cpp` `SqliteStore.cpp`, `tests/support/tls_mock_server.hpp` `TlsMockServer.hpp`. Acronyms are words
  (`SmtpClient`, `HmacSha1`, `IpcKeyFd`), as the type names already spell them.
* When that name is already a type's file in the same directory, the function header takes a `Support` suffix:
  `outbound_transaction.hpp` became `OutboundTransactionSupport.hpp` (`OutboundTransaction.hpp` is the struct) and
  `file_metadata.hpp` `FileMetadataSupport.hpp`. Never make two files differ only in case: Windows and macOS checkouts
  are case-insensitive.
* ADR-0530's test still decides whether a header with one type and functions is renamed after the type or has the
  type extracted. Only the name of what is left changes.

These keep a lower-case name, because they are not module files named for a concept:

* executable entry points: `src/main.cpp`, `src/db_migrate.cpp`, `src/federation_worker/main.cpp`,
  `src/media/thumbnail_worker_main.cpp`, `tests/integration/thumbnail_gate_main.cpp` and
  `tests/tooling/logger_filter_fixture.cpp`, each named after the executable it builds;
* test translation units, `test_*.cpp` and `fuzz_*.cpp`, whose prefixes the test and fuzz guides depend on;
* `include/merovingian/core/not_null.hpp`, because its type is spelled `not_null` (ADR-0467: the file matches the type);
* the C pair `src/canonicaljson/yyjson_adapter.c` and `.h`, which follow C naming and are not C++ module files.

Runtime strings are not file names and keep their spelling: the logger names `http_server`, `media_service`,
`sqlite_store`, `rate_limit` and the rest are what operators put in a log filter (`docs/log-filtering.md`).

Rule for future code: a module header or source is named in PascalCase. A reader never has to guess which scheme a
file uses.

The same change finishes the three type implementations ADR-0530 left in a source named for something else, so every
type's out-of-line members are now in `<TypeName>.cpp`:

* `LandlockHardeningOps`: its constructor and the syscall wrappers it installs were used by nothing else in
  `LandlockHardening.cpp`, so they moved whole to `LandlockHardeningOps.cpp`; no shared header was needed.
* `PostgresqlConnection`: its members and the statement execution only they use moved to `PostgresqlConnection.cpp`.
  The helpers `open_postgresql_connection` shares with them (redacted connection errors, result status,
  `load_result_rows`, `execute_raw_command`) moved to `PostgresqlExecution.cpp`, declared in the module-internal
  `PostgresqlExecution.hpp` in `database::detail` (ADR-0513), and the result deleter has its own header like the
  connection deleter.
* `HttpConnectionDispatcher`: its `Impl` is a nested type, so it is defined in `HttpConnectionDispatcher.hpp` (the
  enclosing type's file), and its members are in `HttpConnectionDispatcher.cpp`. The five transport types it shares
  with `HttpServer.cpp` (`ParkingReservation`, `HttpConnection`, `ConnectionContext`, `ConnectionAdmission`,
  `RoundOutcome`) each have their own header, and `serve_request_round`, `resume_parked_poll` and the receive timeout
  are declared in the module-internal `HttpServerInternal.hpp` in `homeserver::detail`, following
  `ObservabilityInternal.hpp`. A separate internal header for `Impl` was rejected: a nested type stays in its
  enclosing type's file. Both sources log under `http_server`, so the logger name operators filter on is unchanged.

### Positive Consequences

* One naming scheme per directory: a file's name is the name of its type or concept, as written in code.
* The rename is mechanical, so a later reader can repeat it on a stray file without a judgement call.

### Negative Consequences

* A function-only header such as `PolicyEngine.hpp` looks like it declares a `PolicyEngine` type, and does not.
* Every open branch that adds or edits a renamed file meets a rename when it merges.
* Historical records (ADRs, both changelogs) keep the names that were true when written; only their links were
  updated.

## Pros and Cons of the Options

### Keep `snake_case` for function-only files

* Good, because the case tells a reader whether a header declares a type.
* Bad, because a directory mixes two schemes, which the owner asked to end.

### Fold each function-only header into a type header

* Good, because every file would then be named after a type.
* Bad, because ADR-0530 extracted those types on purpose: a function would be found under the name of its result
  struct, and some folds would make headers include each other.

## Links

* Amends [ADR-0467](0467-type-filenames-match-the-type-name-exactly.md): its `snake_case` exception for a header with
  no type no longer applies
* Amends [ADR-0530](0530-a-header-is-renamed-after-its-type-only-when-it-is-about-that-type.md): the header left with
  only functions is PascalCase, not `snake_case`
