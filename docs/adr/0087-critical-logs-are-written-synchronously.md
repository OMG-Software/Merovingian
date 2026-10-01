# Critical logs are written synchronously

* Status: accepted
* Date: 2026-10-01

## Context and Problem Statement

`observability::SingleLog` starts its writer threads after process hardening is installed (ADR-0082). Fatal startup failures are logged at `LogLevel::critical` and then the main thread exits. With writer threads running, those `CRITICAL` lines were queued to bounded writer queues; if the main thread exited before the writers drained, the refusal message was lost. CI integration tests that wait for a specific refusal log line therefore timed out. How do we guarantee that a message logged just before process exit is actually emitted?

## Decision Drivers

* A fatal startup refusal must be visible to operators and to tests that verify hardening behaviour.
* Writer threads must still start only after hardening is installed (ADR-0082).
* The change must not reintroduce synchronous console/file I/O for high-volume log levels.

## Considered Options

1. **Flush the queues and stop writers before exiting after a critical log.** Rejected: the call sites are scattered across startup and hardening self-checks; adding a flush to every fatal path is error-prone and easy to forget.
2. **Make `CRITICAL` bypass the queues and write directly under the existing output locks.** Accepted: it preserves the writer-thread model for every other level, costs no extra state, and cannot be forgotten at a call site.
3. **Keep a separate synchronous `stderr` path for fatal messages only.** Rejected: it duplicates redaction, formatting, and sink-level filtering logic; the existing synchronous path used before `start_writers()` is already correct.

## Decision Outcome

Chosen option: "bypass the queues for `CRITICAL`".

`SingleLog::log()` checks `level >= LogLevel::critical`. For critical messages it calls `console_log_sync()` and `file_log_sync()`, which write under `m_console_out_lock`/`m_file_lock` and flush immediately, exactly as the logger behaves before `start_writers()` is called. Non-critical messages continue to use the asynchronous writer queues.

### Consequences

* Positive: fatal startup messages are guaranteed to reach console and file before the process exits.
* Positive: CI tests that wait for a critical refusal log line see it immediately.
* Positive: no change to the lower-volume lower-severity path; throughput and backpressure behaviour are unchanged.
* Negative: a burst of `CRITICAL` messages is handled on the calling thread; `CRITICAL` is intended for process-ending events, so this is acceptable.

## Related

* `docs/adr/0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md`
