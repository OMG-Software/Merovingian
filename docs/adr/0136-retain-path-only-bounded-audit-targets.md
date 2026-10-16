# Retain path-only, bounded audit targets

* Status: accepted
* Date: 2026-10-12

## Context and Problem Statement

OPS-2 identified request query values reaching durable `audit_log.target` rows and
`audit.append` debug lines. Bounding UTF-8 alone preserves a credential prefix;
redacting selected parameter names cannot protect unknown or encoded names. Audit
construction is also bypassable through aggregate initialisation of an event.

## Considered Options

* Rely on callers to sanitise request targets.
* Retain query strings with a sensitive-parameter allow/deny list.
* Retain only the path or non-HTTP identifier, bounded at the shared audit boundary.

## Decision Outcome

Choose path-only audit targets. `sanitized_audit_target` removes everything from
the first literal question mark and applies the existing 255-byte, control-safe
UTF-8 policy. Its delimiter search and encoding work are bounded by the output
ceiling. `append_local_audit` and `remember_local_audit` use the same value for
logging and storage; audit construction, INSERT statement generation and summaries
also apply this policy so direct event construction cannot bypass those outputs.
Diagnostic HTTP-target redaction remains separate and unchanged.

### Positive Consequences

* Neither known, unknown nor percent-encoded query parameter names can expose a
  query value in a new audit target.
* Routing paths, actors, categories and rejection reasons remain useful for
  investigation, and query-free user/room identifiers retain their meaning.
* Existing UTF-8, control-character and byte bounds remain enforced.

### Negative Consequences

* Audit targets no longer retain even non-sensitive query parameters.
* Existing database rows, backups and historical log files are not rewritten.
  Operators must treat historical audit material as potentially sensitive.
* This does not make arbitrary secret material in a path, actor or reason safe;
  callers must still avoid putting credentials in those fields.

## Verification

The audit-construction regression failed 20 of 21 assertions before the repair.
A separate real SQLite/HTTP regression then failed eight assertions at the shared
sink: durable targets and actual debug output still retained query values even
after constructor repair. With the sink repaired, it passed 22 assertions,
including 429, 503, database reopen, in-memory targets and the non-durable audit
path. Additional bounded UTF-8 and idempotency cases are coverage-only tests.
Independent review rejected the initial capture fixture because it restored an
assumed console level and installed an override for previously inherited policy.
An observable restoration/unwinding regression failed four assertions before
repair. The fixture now uses exact prior threshold/override exchanges, asserts
synchronous writers and redirects the console buffer only after configuration.
Both inherited and explicit policy, including exception unwinding, are covered.
