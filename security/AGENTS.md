# security/ — Security Coding Rules

The authoritative, explained security coding rule set lives in
[`docs/security-coding-rules.md`](../docs/security-coding-rules.md) — every rule, why it
exists, and which module `AGENTS.md` file owns it day to day.

## Contents

| File | Purpose |
|---|---|
| `coding-rules.md` | Pointer to `docs/security-coding-rules.md` (kept for backward-compatible links) |

## When to update `docs/security-coding-rules.md`

Update it when:
- A new vulnerability class is identified in a security review
- A new banned function or pattern is established
- A new mandatory mitigation (e.g., a sanitiser check, a new seccomp rule) is required
- A security-relevant rule is added, changed, or removed in any module `AGENTS.md` file
  (see that document's index-by-source-file section)

Do **not** add general C++ style preferences there — those belong in `docs/coding-rules.md`.
Security rules only: things that, if violated, create a vulnerability.

## Rules

- Every rule in `docs/security-coding-rules.md` should reference a CWE number or a named
  vulnerability class where one applies.
- Changes to the security rule set require a security review comment in the PR.
- `scripts/reject-unsafe.sh` enforces a subset of these rules automatically.
  If you add a new rule that can be grep-detected, add it to that script.
