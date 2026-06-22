# src/net/ — Network Primitives

Low-level TCP acceptor, thread pool, and shutdown coordination.
No Matrix-specific logic lives here.

## Key files

| File | Responsibility |
|---|---|
| `tcp_acceptor.cpp` | Accepts inbound TCP connections; hands off to HTTP layer |
| `listener.cpp` | Binds listening sockets (IPv4 / IPv6 / dual-stack); sets `SO_REUSEADDR`, `CLOEXEC` |
| `thread_pool.cpp` | Fixed-size thread pool; tasks submitted via `post()` |
| `shutdown_signal.cpp` | Catches `SIGTERM` / `SIGINT` and initiates graceful shutdown |

## Rules

- **All sockets must be opened with `O_CLOEXEC` / `SOCK_CLOEXEC`.** File descriptors must not
  leak across `fork()` or `exec()`. Use `FileDescriptor` from `core/file_descriptor.hpp`.
- **Thread pool threads must not throw.** Any exception that escapes a task terminates the
  process. Wrap task bodies in `try/catch` and log the error.
- **Graceful shutdown** drains the thread pool before closing sockets. New connections are
  rejected once shutdown begins; in-flight requests are allowed to complete.
- Prefer the separate `sync_pool` for long-poll sync requests to avoid starving the main pool
  (see `docs/http-transport.md`).
