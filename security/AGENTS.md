# security/ — Security Coding Rules

Contains the authoritative security coding rules for Merovingian.

## Contents

| File | Purpose |
|---|---|
| `coding-rules.md` | Non-negotiable security constraints for every contributor |

## When to update `coding-rules.md`

Update it when:
- A new vulnerability class is identified in a security review
- A new banned function or pattern is established
- A new mandatory mitigation (e.g., a sanitiser check, a new seccomp rule) is required

Do **not** add general C++ style preferences here — those belong in `docs/coding-rules.md`.
This file is security-only: things that, if violated, create a vulnerability.

## Rules

- Every entry in `coding-rules.md` must reference a CWE number or a named vulnerability class.
- Changes to this file require a security review comment in the PR.
- `scripts/reject-unsafe.sh` enforces a subset of these rules automatically.
  If you add a new rule that can be grep-detected, add it to that script.
