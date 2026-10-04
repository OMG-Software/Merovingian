# Commit media moderation with audit and blob state

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Independent moderation writes can report success after failure, or commit removal metadata without consistent blob reference counts. Administrative changes must remain auditable and survive restart coherently.

## Considered Options

* Commit media flags, removal blob reference count and final byte clearing, admin_actions and audit_log in one transaction. Apply repository state and metrics only after commit. Required administrative audit writes are not best-effort rate-gated telemetry.
* Mutate memory first and retry writes later; persist audit separately; copy the entire repository for rollback.

## Decision Outcome

Commit media flags, removal blob reference count and final byte clearing, admin_actions and audit_log in one transaction. Apply repository state and metrics only after commit. Required administrative audit writes are not best-effort rate-gated telemetry.

### Consequences

A failed required write returns 500 and leaves state unchanged. Removing one shared reference retains bytes; removing the final reference clears them. Upload and authentication write failures in DB-5 remain separate work.
