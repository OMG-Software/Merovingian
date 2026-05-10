# Milestone 8: Database persistence and migration scaffold

Milestone 8 introduces the project-owned database persistence boundary needed before adding concrete PostgreSQL/libpq integration.

## Included in Milestone 8

- Prepared statement representation.
- Bound parameter representation with sensitivity metadata.
- Statement-name validation.
- Conservative SQL-shape validation.
- Redacted bound-parameter summaries.
- Database executor interface.
- Validated execution helper that rejects invalid statements before they reach an executor.
- Migration step and migration plan models.
- Forward-only contiguous migration-plan validation.
- Initial schema table inventory covering the Matrix storage areas from the project plan.
- Unit coverage for statement validation, executor gating, redaction, migration planning, and schema inventory.

## Security posture

The database module deliberately does not add libpq yet. The milestone establishes a narrow project-owned boundary first so later database code does not leak dependency-specific types through the homeserver.

The boundary provides these guarantees:

- Application code submits named prepared-statement shapes, not ad hoc SQL execution requests.
- Invalid statement names fail before reaching the executor.
- Obvious multi-statement/comment-shaped SQL is rejected at the boundary.
- Sensitive parameter values can be summarized without leaking the value.
- Migration plans are forward-only and contiguous.
- Core table inventory is explicit and test-covered.

## Deliberately not included

These are deferred to later milestones:

- libpq dependency integration.
- Live PostgreSQL connection management.
- Real query execution.
- Transaction handling.
- Runtime/migration role separation.
- Physical SQL migration files.
- Database-backed users, devices, tokens, rooms, events, media, federation, policy, or audit storage.
- Integration tests against a running PostgreSQL instance.

## Next starting points

1. Add dependency review documentation for libpq.
2. Add RAII wrappers around PostgreSQL connections and results.
3. Add migration-file loading and offline migrator tool scaffolding.
4. Add SQL migration integration tests with a temporary database.
5. Add persistence repositories for users, devices, access-token hashes, and audit events.
