# src/core/ — Core Primitives

Low-level utilities used across all other modules. No module-specific logic lives here.

## Key files

| File | Responsibility |
|---|---|
| `FileDescriptor.cpp` | RAII wrapper for OS file descriptors; closes on destruction, not moveable after close |
| `SecretBuffer.cpp` | Zeroing buffer for sensitive data (tokens, keys); calls `sodium_memzero` on destruction |
| `QueryParams.cpp` | Percent-decode and parse `?key=value&...` query strings from request URIs |
| `PortableSemaphore.cpp` | `PortableSemaphore` (counting semaphore; NetBSD's libc++ has no `std::counting_semaphore`) and `SemaphorePermit`, the RAII owner of one acquired slot |
| `FoldedSubstringMatcher.cpp` | `FoldedSubstringMatcher`: ASCII-case-insensitive substring search in time linear in the text (KMP over folded bytes) with a `steps()` count, and `max_search_term_bytes`, the one cap on a client search term (ADR-0330). Use it for any search of a client's term in text a client chose; never `std::search` or `find` there |
| `FormFields.cpp` | `FormFields::parse`: the strict `application/x-www-form-urlencoded` reader for OAuth bodies and page forms. Any malformed escape, empty or `=`-less field, raw non-printable byte, NUL, invalid UTF-8 or repeated name refuses the whole body; caps 64 KiB, 64 fields, 64-byte names, 8 KiB values (ADR-0765). `FormFields::parse_query`, for the browser pages' query strings only, counts a bare name or an empty field as not sent (RFC 6749 section 3.1) and keeps every other refusal |
| `RequestCookies.cpp` | `RequestCookies::parse`: the `Cookie` header reader. A malformed or repeated cookie makes its own name unusable (`find` answers nothing), never the others (ADR-0766) |
| `HostCookie.cpp` | `host_cookie` / `host_cookie_deletion`: the only `Set-Cookie` writers, `__Host-` names with `Secure`, `HttpOnly`, `Path=/`, `SameSite` from `CookieSameSite`, `Max-Age` |
| `CookieOctets.cpp`, `HttpToken.cpp`, `Utf8.cpp` | `cookie_octets_are_valid`, `http_token_is_valid` (also behind `http::header_name_is_valid`) and `utf8_is_valid` (also behind `canonicaljson::utf8_is_valid`) |
| `CurrentException.cpp` | `current_exception_type_name`: the mangled type name of the exception being handled, `unknown` without the C++ ABI. The one copy for every catch-all that logs a type (ADR-0803); never log the message of a request's exception |
| `LibraryVersion.cpp` | `LibraryVersion`, `describe_library` (static or dynamic, from `dladdr(3)` on an address inside the library, ADR-0222) and the startup log line. Each module reports its own library; core never calls a third-party library's version function |

## Headers-only (no .cpp)

| Header | Purpose |
|---|---|
| `Error.hpp` | `Error` type used with `std::expected<T, Error>` — code + human message |
| `not_null.hpp` | `NotNull<T>` — asserts non-null at construction; avoids raw pointer dereference |
| `SocketHandle.hpp` | RAII socket handle (OS-specific); used by `net/` |
| `BoundedParallel.hpp` | `run_bounded_parallel(count, parallelism, task)`: runs `task(i)` on `std::async` threads, at most `parallelism` at once, joins all, then rethrows the first failure (ADR-0267) |
| `CopyableMutex.hpp` | `CopyableMutex`: a `std::mutex` for a copyable or movable type that guards members. Copy and move make a fresh unlocked mutex; `acquire()` returns the `unique_lock` (ADR-0517) |
| `CopyableConditionVariable.hpp` | `CopyableConditionVariable`: the matching `std::condition_variable` wrapper (`notify_one`, `notify_all`, `wait_until`); not `condition_variable_any`, whose constructor allocates (ADR-0517) |

## Rules

- `SecretBuffer` must be used for any bytes that must not survive past their scope: tokens,
  private key material, passwords in transit. It zeroes memory on destruction even under exceptions.
- `FileDescriptor` must be used for all raw OS fds — never store a bare `int` fd outside RAII scope.
- `query_params` handles percent-decoding per RFC 3986; do not roll your own URL decoding. Read one named parameter
  with `query_parameter` (first match, decoded), never a private loop over the query string.
- `Error` is the only error type for `std::expected` returns — no custom error enums in other modules.
- An OAuth or page form body is read with `FormFields::parse`, never `parse_query_params` or `query_parameter`, which
  accept a malformed escape and a repeated name (ADR-0765). A cookie is read with `RequestCookies::find` and written with
  `host_cookie`: never pick one of two cookies of the same name, and never set a cookie without the `__Host-` prefix
  (ADR-0766). Both readers hold secrets: do not log their values, and do not copy them out further than needed.
- A semaphore slot is only ever returned by a `SemaphorePermit` destructor, never by a hand-written
  `release()` that a throw can skip. Parallel work with a cap goes through `run_bounded_parallel`
  (ADR-0267).
- A mutex that guards members of a copyable or movable type is a `CopyableMutex` held by value
  (ADR-0517), never a `unique_ptr<std::mutex>`. Copying or moving the owner while the mutex is held is a bug.
