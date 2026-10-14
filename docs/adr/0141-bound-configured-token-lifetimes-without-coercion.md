# Bound configured token lifetimes without coercion

* Status: accepted
* Date: 2026-10-14

Technical Story: OPS-4 in `docs/security-audit-report-2026-09-29.md`.

## Context and Problem Statement

The signed lifetime parser correctly preserves representable integers, but
positive values up to the signed maximum lacked configuration-policy bounds.
An oversized finite lifetime must not silently become a non-expiring credential.
Negative admission and no-expiry response omission are separate earlier repairs.

The new real parser/direct-typed validation regression reproduced 20 missing
rejections with 126 passing controls across both fields. Normal unit GREEN now
passes 146 assertions / 1 upper-bound case, 20 / 1 negative-admission case,
4 / 2 signed-boundary cases and 991 / 177 configuration cases, with 61 sources
stable during execution. Independent source review passed without security or
logic findings or suggestions; parent checks bind the reviewed production,
regression and registration to executed GREEN. Fresh full acceptance passed
56 targets, all return codes zero, no failures/timeouts and 170 stable files
including all 61 focused sources. Parent independently reconciled archived
JSON/text and reviewed-source bindings before accepting this bounded slice and
releasing the freeze. Only acceptance-status docs changed afterward. This is not
whole OPS-4 closure.

## Decision Drivers

* Preserve the explicit zero/no-expiry sentinel and existing positive defaults.
* Enforce a practical, inclusive ceiling independently for each credential kind.
* Keep generic signed numeric parsing correct and preserve invalid typed values
  for field-specific findings rather than silently replacing them.
* Do not rewrite stored timestamps, predecessor links or historical digests.
* Do not mistake a policy ceiling for checked clock arithmetic or a runtime
  publication guard.

## Considered Options

* Admit every representable positive signed integer.
* Bound only by the host clock's convertible duration range.
* Silently clamp or substitute defaults for oversized values.
* Apply project policy ceilings in the existing typed validator without coercion.

## Decision Outcome

Chosen option: "Apply project policy ceilings in the existing typed validator
without coercion". Access lifetimes admit 0 through 2,592,000,000 milliseconds
(30 days); refresh lifetimes admit 0 through 31,536,000,000 milliseconds
(365 days). Both endpoints are inclusive. Zero remains the explicit no-expiry
choice. Defaults remain one hour for access and 30 days for refresh.

These are project security-policy limits, not Matrix protocol maxima. Access has
a shorter finite ceiling because it directly authorizes requests; refresh retains
a longer finite window for renewal. Disabling expiry remains an explicit operator
choice rather than an accidental result of oversized input.

Parsing still retains the exact signed integer. `validate` reports the exact
field for oversized values; `is_valid` reports false. The parser's findings expose
the same policy error. No parser coercion, stored-data migration or automatic
revocation is introduced.

### Positive Consequences

* Off-by-one and signed-maximum inputs are rejected without loss of provenance.
* Zero, one millisecond, defaults and inclusive maxima remain admitted.
* The same policy applies to parsed and directly constructed values when the
  existing typed validator is invoked.

### Negative Consequences

* Operators with longer configured finite lifetimes must shorten them before
  passing validation. Existing stored sessions are not changed by validation.
* Public typed runtime snapshot/reload APIs still need their own publication
  guard; a reload classification is not validation.
* Checked duration conversion and timestamp addition remain required. Positive
  arithmetic failure must not return the successful no-expiry representation.
* Persisted-expiry hydration and registration-response coverage remain separate.

## Pros and Cons of the Options

### Representable-range or clock-range bounds only

* Good: retains the broadest input compatibility.
* Bad: representability is not a practical lifetime policy, and duration
  conversion alone does not prove timestamp addition safe.

### Silent clamping or default substitution

* Good: avoids an explicit configuration failure.
* Bad: hides the operator's rejected input and can make advertised policy differ
  from intended policy. Substituting absence could disable expiry.

## Links

* Regression: `tests/unit/test_token_lifetime_policy.cpp`.
* Validator: `src/config/config.cpp`.
* Operational configuration: `docs/user-manual.md`.
