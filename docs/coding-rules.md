# Coding rules

This document records project coding rules that apply across production code, tests, tools, and generated scaffolding.

## Tests

All tests must be structured in Given/When/Then form.

Use explicit section comments inside each test case:

```cpp
// Given
// setup inputs, fixtures, and preconditions

// When
// execute the behavior under test

// Then
// assert expected results
```

Rules:

- Keep setup in `// Given`.
- Keep the single behavior under test in `// When` where practical.
- Keep assertions in `// Then`.
- Prefer one behavior per test case.
- Avoid hidden setup inside assertion expressions when it obscures the Given/When/Then structure.
