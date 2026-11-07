# src/ — Implementations

A `.cpp` file here normally mirrors the header of the same name at the same relative path in `include/merovingian/`. Two do not: `database/sqlite_store.cpp` and `federation_worker/main.cpp` have no header. Some headers have no `.cpp`.
Module directory names match: `src/auth/` ↔ `include/merovingian/auth/`.

## File conventions

- First line: `// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later`
- Follow [the coding guide's include order](../docs/coding-rules.md#calls-formatting-and-includes).
  The root `.clang-format` enforces its groups.
- File-local helpers belong in an anonymous `namespace { }` block — never pollute the module namespace

## Key code patterns

- Mark all functions `[[nodiscard]]` unless the return value is intentionally discardable
- Mark functions `noexcept` only when no exception can escape. Check callees and cleanup paths: the annotation does not prove the body cannot throw; an escaping exception terminates the process.
- Destructors must not throw; annotate `noexcept` explicitly
- Avoid `static` local variables in functions that may be called from multiple threads

## Error handling

Use `std::expected<T, merovingian::core::Error>` for fallible operations.
Return errors as values; do not throw for expected failure paths (invalid input, missing resource, etc.).
Reserve exceptions for truly unexpected conditions (programmer errors caught in tests, not production flow).

## Where module-local helpers go

- Used only within one `.cpp` → anonymous `namespace { }` in that `.cpp`, including helper classes and
  structs; these do not count against the one-type-per-file rule
- Shared across multiple `.cpp` files in the same module → move it, never copy it. A shared helper class or
  struct gets its own `include/merovingian/<module>/<TypeName>.hpp` (and `.cpp` when needed); shared helper
  functions go in a module-internal header in `include/merovingian/<module>/` (exposed in the header but not
  intended as public API). See [ADR-0513](../docs/adr/0513-single-file-helper-types-stay-in-the-anonymous-namespace.md)

## Includes

Use quotes for project headers, angle brackets for standard library and third-party:

```cpp
#include "merovingian/module/name.hpp"

#include <curl/curl.h>
#include <sodium.h>

#include <algorithm>
```

Never use bare relative includes (`#include "name.hpp"` without the `merovingian/` path prefix).
The one existing exception is `src/federation_worker/`, whose `WorkerEventLoop.hpp` lives beside
its `.cpp` and is included relatively; do not add others.
