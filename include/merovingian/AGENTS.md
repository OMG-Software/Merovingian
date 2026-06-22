# include/merovingian/ — Public Headers

Public API lives here. Every header must be self-contained (transitively include all dependencies it exposes).
The directory mirrors `src/` 1:1: `include/merovingian/auth/` ↔ `src/auth/`.

## File conventions

```cpp
// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/module/dependency.hpp"
#include <standard_header>
```

- `// SPDX-...` first, then `#pragma once`, then includes
- Quotes for project headers (`"merovingian/..."`), angle brackets for STL and third-party
- No bare relative includes (`"name.hpp"` without the `merovingian/` prefix)
- One primary type per file; filename matches the primary type in `snake_case`

## Namespace

Every declaration lives in `merovingian::<module>::` matching the subdirectory name.
No `using namespace` in headers — ever.

## What belongs here vs. src/

Headers declare interfaces; `.cpp` files implement them.

- Function declarations: header
- Class member declarations: header
- Function bodies: `.cpp` (unless `inline`, `constexpr`, or template)
- Helper types used only within one `.cpp`: anonymous namespace in that `.cpp`

## Forward declarations

Prefer forward declarations over full `#include` when only a pointer, reference, or `std::unique_ptr<T>` is needed.
Full `#include` is required when the type's size or member layout is needed (by-value storage, inheritance, calling methods).

## Design constraints

- Headers expose the minimum surface required — avoid public fields on classes
- Prefer `[[nodiscard]]` on returned handles and result types
- Mark all non-mutating member functions `const`
- Mark functions that cannot throw `noexcept`
