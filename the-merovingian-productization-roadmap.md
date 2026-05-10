# Productization Roadmap Addendum

This addendum updates the project direction after the early scaffold milestones.

The project has enough subsystem scaffolding to stop expanding placeholder surfaces and start converting those surfaces into end-to-end runtime behavior. Future milestones should be product slices first and additional scaffolding only when it is directly needed to complete a working path.

## Direction change

Milestones after runtime hardening should prioritize complete, executable behavior over additional standalone policy or model scaffolds.

A milestone is product-oriented when it:

- starts from validated runtime configuration;
- runs through the actual server executable or runtime listener;
- persists or reads real data where persistence is part of the path;
- uses existing policy, observability, database, auth, media, federation, and hardening scaffolds rather than bypassing them;
- includes integration coverage that exercises a user-visible or operator-visible workflow;
- emits safe audit, metric, health, and log summaries without secrets or event contents.

A milestone is scaffold-oriented when it only adds interfaces, data models, notes, or isolated policy functions. Scaffold-only milestones should be deferred unless they unblock a product slice.

## Revised milestone sequence

### Milestone 17: minimal runnable homeserver vertical slice

Issue: #27

Goal: boot a local server and complete one local homeserver path through real runtime behavior.

Required outcomes:

- Runtime starts an actual HTTP listener from validated config.
- Admin health endpoint returns a safe observability summary.
- Database connection opens and validates an initial schema.
- Local auth works end-to-end: create/register user, login, authenticated request, logout/session invalidation.
- Minimal room flow works end-to-end: create room, join room, send event, fetch event or room state.
- Audit log appends real auth/admin events.
- Existing scaffolds are used rather than bypassed.
- Integration test boots the server and exercises the full path.

### Milestone 18: client-server MVP API completion

Issue: #28

Goal: expand the vertical slice into a usable MVP Client-Server API surface.

Required outcomes:

- Client API routing runs through the real listener.
- Authenticated endpoints use the real session/token path.
- MVP account/device endpoints exist.
- MVP room endpoints exist.
- Basic sync endpoint exists with bounded response construction.
- Matrix-style error responses are stable.
- Rate limits and request limits are enforced at endpoint boundaries.
- Integration tests cover auth, rooms, send, state, and sync.

### Milestone 19: persistence, migrations, and schema hardening

Issue: #44

Goal: convert database scaffolds into durable runtime storage and migration behavior.

Required outcomes:

- Initial schema exists for users, devices, access tokens, rooms, membership, events, state, audit log, and admin actions.
- Migration runner applies ordered migrations and records applied versions.
- Runtime startup validates schema compatibility before accepting traffic.
- Runtime DB access uses RAII handles and prepared statements only.
- Auth tokens are hashed at rest.
- Integration tests cover fresh bootstrap, idempotent startup, migration ordering, and schema mismatch fail-closed behavior.

### Milestone 20: federation MVP with signed request handling

Issue: #45

Goal: build a minimal real federation path on top of signing, discovery, event, and policy scaffolds.

Required outcomes:

- Federation listener routes inbound requests through the HTTP runtime.
- Server signing key loading and request signing boundaries are implemented without secret logging.
- Inbound request authentication verifies origin, signature metadata, and time bounds where applicable.
- Minimal discovery/key-fetch path exists behind timeout and private-address protections.
- MVP transaction handling accepts or rejects PDUs through event authorization scaffolds.
- Federation quarantine and remote backoff decisions are enforced at runtime.
- Integration tests cover signed acceptance, malformed signature rejection, private-address rejection, and quarantined remote rejection.

### Milestone 21: media upload, download, and quarantine MVP

Issue: #46

Goal: convert media security scaffolds into a working local media repository MVP.

Required outcomes:

- Authenticated local upload endpoint exists with limits, MIME validation, content hashing, and quarantine hooks.
- Local download endpoint serves stored media without exposing filesystem paths or unsafe metadata.
- Hash-based deduplication is enforced.
- Admin quarantine/release/remove actions operate on stored media records.
- Remote media fetch remains disabled or fails closed until a later milestone.
- Integration tests cover upload, download, deduplication, quarantine, release, and rejected unsafe uploads.

### Milestone 22: conformance, fuzz, and release-readiness gates

Issue: #49

Goal: add release-readiness tests after real behavior exists.

Required outcomes:

- Matrix conformance fixtures are wired where practical.
- Client API, federation, database migration, state-resolution, signature, media, and platform hardening suites exercise real runtime behavior.
- Fuzz targets cover parsers and protocol-critical logic now present in product paths.
- Property tests cover canonical JSON, event/state invariants, and authorization decisions.
- Upgrade/downgrade tests cover database schema versions.
- CI policy records required gates before merge/release.

### Milestone 23: packaging, deployment, and release hardening evidence

Issue: #50

Goal: add production packaging and release evidence after MVP behavior and release-readiness gates exist.

Required outcomes:

- Packaging exists for systemd, OpenRC, rc.d, Docker, deb, rpm, pkg, and nix where practical.
- Hardened deployment guides exist for Linux and BSD.
- Release artifacts record compiler, linker, runtime hardening, dependency, and CI evidence.
- Production config profile is documented and validated.
- Security review checklist covers dependencies, secrets, audit logging, observability redaction, federation, media, and runtime hardening.
- Release checklist is CI-gated.

## Backlog discipline

From this point forward:

- Do not create a new scaffold-only milestone unless it directly unlocks one of the product milestones above.
- Prefer vertical end-to-end tests over isolated model tests when adding behavior.
- Keep scaffold APIs only if a product path calls them.
- Remove or collapse unused scaffolds when a product path proves they are unnecessary.
- Every milestone should produce a user-visible, operator-visible, or protocol-visible capability.

## Immediate next step

Finish and merge Milestone 16, then begin Milestone 17 as the first runnable homeserver vertical slice.
