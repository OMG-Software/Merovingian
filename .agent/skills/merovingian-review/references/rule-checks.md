# Rule checks

Checks drawn from [docs/coding-rules.md](../../../../docs/coding-rules.md) (CR) and
[docs/security-coding-rules.md](../../../../docs/security-coding-rules.md) (SCR), cited as `doc#heading`. The
documents are binding. These lines are for finding where to look.

## Already enforced: do not re-report

Report these only if the diff edits or bypasses the gate itself.

| Gate | Runs in | Fails on | Misses |
|---|---|---|---|
| `scripts/reject-unsafe.sh` | CI (`ci.yml`, `static-analysis.yml`) and pre-commit | naked `new`/`delete`/`malloc`/`calloc`/`realloc`; `(void)` and `static_cast<void>` discards; `shared_ptr` without `// SHARED_PTR: reviewed — <reason>`; `.unlock()` without `// LOCK_RELEASE: reviewed — <reason>`; libsodium outside its directories | whether the "reviewed" reason is **true**; patterns split across lines; files outside its roots |
| `check-catch2-bdd-tests.sh` | meson test | `TEST_CASE`, missing SCENARIO/GIVEN/WHEN/THEN words in `tests/unit` | per-scenario structure; conformance and integration files |
| `check-unit-test-registration.sh` | meson test | unit or conformance file not in `tests/meson.build` | integration files |
| `check-unit-test-isolation.sh` | meson test | unit file naming `start_runtime` and the other runtime builders | a helper that builds a runtime |
| `tests/tooling/test_include_order.py` | meson test | include grouping and order | — |
| `tests/tooling/test_changelog_format.py` | meson test | CHANGELOG heading and bullet format; newest entry equals `meson.build` version | whether the bullet describes **this** change |
| `tests/tooling/test_line_endings.py` | meson test | CRLF | — |
| clang-tidy | CI `static-analysis.yml` | its configured checks | — |

**Not enforced in CI:** `check-staged-changelog-docs.sh` runs only in the local pre-commit hook, which may not be
installed. The format tool `scripts/format_code.py` runs by hand only. So a missing CHANGELOG bullet or doc
update, and formatting drift, are review items. Report formatting in one line, never per hunk.

## Grep on the changed lines

Run each pattern over `git diff -U0 <base>...<head>` added lines (`^\+`), then read each hit in context.

| Check | Pattern | Source |
|---|---|---|
| Raw fd held as `int` outside `FileDescriptor` | `\bint\s+\w*fd\b` | SCR#Memory safety and resource ownership |
| fd or socket without CLOEXEC | `\b(socket\|accept\|open\|pipe\|dup2?)\(` | SCR#Memory safety and resource ownership |
| Unchecked narrowing | `static_cast<(u?int\d+_t\|int\|short\|unsigned)>` on sizes | CR#Errors and function contracts |
| Destructor without `noexcept` | `~\w+\(\)` | CR#Errors and function contracts |
| `sodium_memzero` outside the crypto boundary (use `core::secure_zero`) | `sodium_memzero` | SCR#Memory safety and resource ownership |
| Non-constant-time secret compare | `memcmp\|std::equal\|==` near token, hash, secret | SCR#Cryptography |
| Log to stdout or stderr instead of `SingleLog` | `std::cout\|std::cerr\|fprintf\(stderr` | SCR#Secrets and logging |
| Config or env read outside the snapshot | `getenv\|secure_getenv` | SCR#Secrets and logging |
| Interpolated SQL, ad-hoc DDL, backend downcast | `ALTER TABLE\|dynamic_cast<.*(Sqlite\|Postgres)`; string-built SQL | SCR#Database |
| Bare SQLite prepare or step | `sqlite3_prepare_v2\|sqlite3_step` | SCR#Database |
| Clearing a revoked flag | `revoked\s*=\s*(false\|0)` | SCR#Database |
| Direct header indexing | `headers\[` | SCR#HTTP and network boundary |
| Ad-hoc HTTP or cleartext | `curl_easy_\|allow_cleartext_http` | SCR#HTTP and network boundary |
| Blocking socket mode, raw TLS I/O | `O_NONBLOCK\|SSL_read\|SSL_write\|TIMEO` | SCR#HTTP and network boundary |
| ID split on the last colon | `rfind\(':'\)` | SCR#Authentication and authorization |
| Hard-coded room version logic | `room_version\s*==` | SCR#Federation |
| Regex or naive search on caller input | `std::regex\|regex_search\|std::search\|\.find\(` | SCR#Sync; SCR#Push notifications |
| Seccomp without TSYNC | `seccomp\(` | SCR#Platform hardening |
| Recursive mutex swap | `recursive_mutex` | CR#Concurrency and portability |
| Banned concurrency primitives | `jthread\|stop_token\|stop_source\|counting_semaphore` | CR#Concurrency and portability |
| Mutex behind a pointer in a copyable type | `(unique\|shared)_ptr<std::mutex>` | CR#Concurrency and portability |
| `mutable` cache of a non-thread-safe type | `\bmutable\b` | CR#Concurrency and portability |
| Test-only master key in production code | `support/MasterKey` outside `tests/` | SCR#Testing requirements for security-critical code |
| Unpinned third-party action | `uses: [^./][^@]+@v` | CR#Change workflow |
| `using namespace` in a header | `using namespace` in `include/` | CR#Design and interfaces |
| Bare project include | `#include "[^m]` | CR#Calls, formatting, and includes |
| A second type in one file; file stem differs from the type name | new `class\|struct\|enum` in a file that already has one | CR#Design and interfaces (ADR-0514, ADR-0596) |

## Judgement checks

| Question | Source |
|---|---|
| Is inbound federation authenticated before any body byte is read? Is a bad signature charged to the source address, not the claimed origin? | SCR#Federation |
| Does every inbound PDU path verify signatures against the sender's keys before the graph? | SCR#Federation |
| Does main re-verify everything the worker relays, bind relays to a main-verified digest or permit, and judge ACL and policy itself? | SCR#Federation; `docs/security-review-checklist.md#Federation worker IPC` |
| Is the event or state change authorised (room-version-aware) before it is persisted? Is authority taken from recorded state rather than the event's cited `auth_events`? | SCR#Authentication and authorization |
| Does local membership change only through `persist_composed_event`, in one transaction with the event and `current_state`? | SCR#Authentication and authorization |
| Is `runtime.mutex` released around every blocking call, with protected state untouched while released? | CR#Concurrency and portability; SCR#HTTP and network boundary |
| Does every client-triggered outbound call take an `admit_client_outbound_proxy` slot and run under one `OutboundDeadline`? | SCR#HTTP and network boundary (ADR-0079) |
| Is everything a client or remote can grow capped and refused, with cost at most linear under the lock? | SCR#HTTP and network boundary; SCR#Sync; SCR#Push notifications |
| Does a large-body route authenticate before reading, with an explicit opt-out from the 64 KiB cap? | SCR#HTTP and network boundary |
| Do identity, push, media and preview fetches resolve through `deny_ip_ranges`, over HTTPS? | SCR#Identity Service client; SCR#HTTP and network boundary |
| Are variable-length secrets hashed with domain separation before comparison? | SCR#Cryptography |
| Is a secret file checked and read through one descriptor? | SCR#Cryptography |
| Do client read paths use `HistoryVisibility` and `room_read_access_for`? Can a not-found or presence answer enumerate users? | SCR#Sync |
| Is every unauthenticated-triggerable audit event rate-gated and size-bounded? | SCR#Secrets and logging |
| Does every hardening step run before the first socket and thread? Does each isolated child get its own profile? | SCR#Platform hardening |
| Is every `noexcept`, `[[nodiscard]]`, `SHARED_PTR` and `LOCK_RELEASE` marker's rationale actually true? | CR#Ownership and resource lifetime; CR#What automated checks cover |
| Did a performance change skip validation, bounds, authorisation, signature checks or redaction? | SCR#Process |
| Does a new shared type have a concurrency scenario? | SCR#Testing requirements for security-critical code |
| If a module `AGENTS.md` security rule changed, is `docs/security-coding-rules.md` changed with it? Is a new grep-detectable rule added to `reject-unsafe.sh`? | `docs/AGENTS.md`; `security/AGENTS.md#Rules` |

## Known inconsistencies in the guidance

When a finding rests on one of these, read the code and cite what it actually does.

- `docs/coding-rules.md` names `RuntimeLockRelease.hpp` for releasing the runtime lock, while
  `docs/security-coding-rules.md` names `RequestLockScope.hpp`. Both headers exist. Check which one the code
  path uses before citing either.
- `docs/security-coding-rules.md#Federation` states the inbound-event tip-status rule twice: per room for senders
  without power (ADR-0695), and "never per room". The ADR is the tie-breaker.
- `[[nodiscard]]` is "all functions" in `src/AGENTS.md`, "returned results" in CR, and "prefer" in
  `include/merovingian/AGENTS.md`. Hold a diff to CR.
- `src/federation/AGENTS.md` rule 1 says to answer 401 for a bad X-Matrix signature. Check the handler and the
  spec before citing a status code.
