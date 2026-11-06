# Use std::invoke for callable dispatch and immediate lambdas

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The proposed call-style rule did not distinguish ordinary function calls from
generic callable dispatch and immediately invoked lambdas. A blanket rule would
replace familiar named calls without addressing the hard-to-see trailing `()`
on a lambda body.

## Considered Options

* Use `std::invoke` for every function call.
* Use it for generic callable dispatch and immediately invoked lambdas; keep
  ordinary named calls as `function(arguments)`.
* Add no call-style rule.

## Decision Outcome

Chosen option: the scoped rule, as selected by the project owner. It makes an
immediate lambda invocation explicit at the start of the expression and gives
generic dispatch one form, while preserving ordinary named call syntax.

This is a review rule, not a check implemented by `reject-unsafe.sh`. It guides
new and changed code; this documentation change does not migrate existing calls.
The rule is recorded in [coding rules](../coding-rules.md#calls-formatting-and-includes).

### Positive Consequences

* The scope is explicit, so reviewers need not infer what "trailing parentheses" means.
* Ordinary function calls retain their usual form.

### Negative Consequences

* Immediate lambdas require `<functional>` and slightly more syntax.
* Reviewers must distinguish generic dispatch from an ordinary named call.
