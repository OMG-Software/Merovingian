# Suppress all PostgreSQL connection options in diagnostics

* Status: accepted
* Date: 2026-10-13

## Context and Problem Statement

DB-9 identifies credential fragments escaping token-based redaction when libpq
options use spaces, quotes or escapes. The original remediation suggests never
logging the connection string and retaining only host/database names. Those
option values can themselves contain sensitive material, so reconstructing an
operator-facing summary is not an adequate confidentiality boundary.

The existing connection opener already returns a fixed redacted identity,
discards parser diagnostic text and uses a fixed connection-status failure
reason. Preserve that guard rather than replacing it with a new string masker.
This record documents the retained policy, not a new production repair.

## Decision Drivers

* Suppress complete and partial credential bytes across supported option syntax.
* Keep returned failure diagnostics as confidential as emitted records.
* Preserve libpq parsing, connection ownership and existing persisted formats.
* Test the actual diagnostic sink and backend-failure branch, not only a helper.

## Considered Options

* Retain a fixed identity and generic parser/connection-failure reasons.
* Parse connection options and emit only selected host/database values.
* Redact password tokens from the supplied connection string.
* Forward raw parser or connection errors to improve operator diagnostics.

## Decision Outcome

Chosen option: retain a fixed identity and generic failure reasons. The opener
must not emit supplied connection options or return them as diagnostic identity.
Parser error storage is freed without forwarding its contents. The connection
status failure reason contains no library error detail. Existing allocation and
startup-command refusal reasons remain fixed. Reconnect callers reuse the same
opener; the persistent-store wrapper forwards its sanitized failure reason.

### Positive Consequences

* Spaces, quotes, escapes and URI encoding cannot restore option bytes to the
  first-party opener's structured records or returned diagnostic identity.
* No connection-option parser needs to be reimplemented for logging.
* The compatibility redaction API remains available without exposing host,
  database, user, password or other supplied option values.

### Negative Consequences

* Operator logs cannot identify the configured endpoint or underlying library
  error from a connection failure alone.
* Diagnostic investigation must use protected configuration and controlled
  checks rather than enabling raw connection-option logging.

## Verification and Scope

The existing DB-9 unit scenario passes 6 assertions / 1 case. New registered
integration coverage passes 85 / 2 through the actual synchronous DEBUG console
sink. It exercises malformed quoted-option rejection and four policy-admitted
quoted, spaced, escaped and URI forms against a never-created socket directory
under an owned private temporary parent. Admission controls and exact generic
reasons distinguish parser rejection from the real libpq connection-status
failure branch. Required opening/rejection records prevent disabled logging
from producing a vacuous pass. Runtime-only marker components are absent from
records, returned reason and returned identity; assertions expose booleans only.
The tests also check restored environment/stdout and owned-parent removal.
Normal database integration passes 2628 / 58 against the same 30-source manifest.
These are additional first-GREEN checks of an existing guard, not a new RED/fix
cycle. Bounded independent source review passed without security or logic
findings; parent inspection bound the reviewed sources to the current executed
manifests. Current database units pass 18363 / 174, DB-8 units 48 / 2 and DB-6
integration 2733 / 15. The fresh combined checkpoint passed 56 OK targets,
all return codes zero and no failures/timeouts, with 139 unchanged snapshotted
files including all 30 focused sources. Source freeze ended after parent
inspection of the completed archives and current-source binding.

The capture fixture requires serialized in-process execution and no singleton
asynchronous logger writers. It restores exact console threshold and module
override presence/value. The socket-specific scenario explicitly skips native
Windows rather than falling back to TCP or an ambient database. No test database
service, production connection, new authentication callback or fake log sink is
used. Live authentication/TLS/ready branches, allocation/startup fault injection,
general SQL-result error confidentiality and release acceptance are outside this
coverage. No schema, role, stored-data or connection-admission policy changes.

## Links

* [ADR-0138: Require explicit remote PostgreSQL TLS policy](0138-require-explicit-remote-postgresql-tls-policy.md)
