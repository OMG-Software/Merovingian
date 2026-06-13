# src/ — Implementations

Every `.cpp` file here mirrors a header in `include/merovingian/` at the same relative path.
Module directory names match: `src/auth/` ↔ `include/merovingian/auth/`.

## File conventions

- First line: `// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later`
- Include order: matching header first, then standard library (`<algorithm>`, `<string>`, …), then third-party
- File-local helpers belong in an anonymous `namespace { }` block — never pollute the module namespace

## Key code patterns

- Mark all functions `[[nodiscard]]` unless the return value is intentionally discardable
- Mark functions `noexcept` when they cannot throw — the compiler enforces this
- Destructors must not throw; annotate `noexcept` explicitly
- Avoid `static` local variables in functions that may be called from multiple threads

## Error handling

Use `std::expected<T, merovingian::core::Error>` for fallible operations.
Return errors as values; do not throw for expected failure paths (invalid input, missing resource, etc.).
Reserve exceptions for truly unexpected conditions (programmer errors caught in tests, not production flow).

## Where module-local helpers go

- Used only within one `.cpp` → anonymous `namespace { }` in that `.cpp`
- Shared across multiple `.cpp` files in the same module → module-internal header in `include/merovingian/<module>/`
  (exposed in the header but not intended as public API)

## Includes

Use quotes for project headers, angle brackets for standard library and third-party:

```cpp
#include "merovingian/module/name.hpp"   // project header — quotes
#include <algorithm>                      // standard library — angle brackets
#include <sodium.h>                       // third-party — angle brackets
```

Never use bare relative includes (`#include "name.hpp"` without the `merovingian/` path prefix).
