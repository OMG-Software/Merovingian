# src/core/ — Core Primitives

Low-level utilities used across all other modules. No module-specific logic lives here.

## Key files

| File | Responsibility |
|---|---|
| `file_descriptor.cpp` | RAII wrapper for OS file descriptors; closes on destruction, not moveable after close |
| `secret_buffer.cpp` | Zeroing buffer for sensitive data (tokens, keys); calls `sodium_memzero` on destruction |
| `query_params.cpp` | Percent-decode and parse `?key=value&...` query strings from request URIs |

## Headers-only (no .cpp)

| Header | Purpose |
|---|---|
| `error.hpp` | `Error` type used with `std::expected<T, Error>` — code + human message |
| `not_null.hpp` | `NotNull<T>` — asserts non-null at construction; avoids raw pointer dereference |
| `socket_handle.hpp` | RAII socket handle (OS-specific); used by `net/` |

## Rules

- `SecretBuffer` must be used for any bytes that must not survive past their scope: tokens,
  private key material, passwords in transit. It zeroes memory on destruction even under exceptions.
- `FileDescriptor` must be used for all raw OS fds — never store a bare `int` fd outside RAII scope.
- `query_params` handles percent-decoding per RFC 3986; do not roll your own URL decoding.
- `Error` is the only error type for `std::expected` returns — no custom error enums in other modules.
