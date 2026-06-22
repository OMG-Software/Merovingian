# src/trust_safety/ — Trust & Safety Module

Policy engine for content and user moderation.

## Key files

| File | Responsibility |
|---|---|
| `policy_engine.cpp` | Evaluates content against configured policy rules; returns allow/deny/flag decisions |

## Rules

- Policy decisions are **advisory by default** — the engine flags content; enforcement
  (blocking, banning) is applied by the calling module based on the decision.
- Policy rules are loaded from config at startup and can be hot-reloaded.
- **Never hard-code moderation decisions in this module.** All rules come from config
  or an operator-supplied policy file.
- Policy engine decisions must be logged at DEBUG level with the rule that triggered them.

## Key doc

- `docs/trust-safety.md` — policy rule format, moderation workflow, operator configuration
