# src/core/ — Core Primitives

Low-level utilities used across all other modules. No module-specific logic lives here.

## Key files

| File | Responsibility |
|---|---|
| `file_descriptor.cpp` | RAII wrapper for OS file descriptors; closes on destruction, not moveable after close |
| `secret_buffer.cpp` | Zeroing buffer for sensitive data (tokens, keys); calls `sodium_memzero` on destruction |
| `query_params.cpp` | Percent-decode and parse `?key=value&...` query strings from request URIs |
| `portable_semaphore.cpp` | `PortableSemaphore` (counting semaphore; NetBSD's libc++ has no `std::counting_semaphore`) and `SemaphorePermit`, the RAII owner of one acquired slot |
| `library_version.cpp` | `LibraryVersion`, `describe_library` (static or dynamic, from `dladdr(3)` on an address inside the library, ADR-0222) and the startup log line. Each module reports its own library; core never calls a third-party library's version function |

## Headers-only (no .cpp)

| Header | Purpose |
|---|---|
| `error.hpp` | `Error` type used with `std::expected<T, Error>` — code + human message |
| `not_null.hpp` | `NotNull<T>` — asserts non-null at construction; avoids raw pointer dereference |
| `socket_handle.hpp` | RAII socket handle (OS-specific); used by `net/` |
| `bounded_parallel.hpp` | `run_bounded_parallel(count, parallelism, task)`: runs `task(i)` on `std::async` threads, at most `parallelism` at once, joins all, then rethrows the first failure (ADR-0267) |

## Rules

- `SecretBuffer` must be used for any bytes that must not survive past their scope: tokens,
  private key material, passwords in transit. It zeroes memory on destruction even under exceptions.
- `FileDescriptor` must be used for all raw OS fds — never store a bare `int` fd outside RAII scope.
- `query_params` handles percent-decoding per RFC 3986; do not roll your own URL decoding.
- `Error` is the only error type for `std::expected` returns — no custom error enums in other modules.
- A semaphore slot is only ever returned by a `SemaphorePermit` destructor, never by a hand-written
  `release()` that a throw can skip. Parallel work with a cap goes through `run_bounded_parallel`
  (ADR-0267).
