# src/net/ — Network Primitives

Low-level TCP acceptor, thread pool, and shutdown coordination.
No Matrix-specific logic lives here.

## Key files

| File | Responsibility |
|---|---|
| `tcp_acceptor.cpp` | Opens and binds listening sockets with `SOCK_CLOEXEC` and `SO_REUSEADDR`; accepts inbound TCP connections and hands them to the HTTP layer |
| `listener.cpp` | Builds `ListenerPlan` / `RuntimeListeners` from config (client and federation bind addresses, TLS settings); makes no socket calls |
| `thread_pool.cpp` | Fixed-size thread pool; tasks submitted via `submit()`; `worker_count()` sizes the dispatcher's caps |
| `connection_parker.cpp` | `ConnectionParker`: one `poll(2)` thread holding connections that wait for input; hands a connection out only once readable, under a global and a per-client cap with an RAII `ActiveShare` (ADR-0077) |
| `shutdown_signal.cpp` | Catches `SIGTERM` / `SIGINT` and initiates graceful shutdown |

## Rules

- **All sockets must be opened with `O_CLOEXEC` / `SOCK_CLOEXEC`.** File descriptors must not
  leak across `fork()` or `exec()`. Use `FileDescriptor` from `core/file_descriptor.hpp`.
- **Thread pool threads must not throw.** Any exception that escapes a task terminates the
  process. Wrap task bodies in `try/catch` and log the error.
- **Graceful shutdown**: stop accepting, then stop the `ConnectionParker` (it closes every
  parked connection at once and joins its thread; it does no blocking I/O, so this is bounded),
  then drain the thread pools. In-flight requests are allowed to complete; a connection a worker
  hands back after the parker has stopped is closed, not parked.
- **No worker waits on a quiet socket (ADR-0077).** Waiting for input — a first byte, the next
  keep-alive request — is the `ConnectionParker`'s job. A pool task that would block on a
  connection with nothing to read is the defect HTTP-1 fixed.
- **`ConnectionParker` locking**: one internal mutex, a leaf. It is never held while polling,
  closing a connection, calling a `Connection` method or running the dispatch callback, so the
  callback may call `park()` and release `ActiveShare`s freely. A connection is owned by exactly
  one of the parker and the holder of the `Dispatched` value it was handed out in.
- **No thread before hardening (ADR-0082)**: the parker's thread starts only in `start()`; the
  thread pools start in their constructors, so construct both after hardening.
- Prefer the separate `sync_pool` for long-poll sync requests to avoid starving the main pool
  (see `docs/http-transport.md`).
- `ThreadPool`'s optional `on_thread_start` constructor callback runs once per worker thread
  before it dequeues any work — use it to install thread_local state a worker's callbacks will
  need (e.g. the homeserver's audit-sink database pointer, see
  `docs/observability-audit.md`), not to do per-task setup.
