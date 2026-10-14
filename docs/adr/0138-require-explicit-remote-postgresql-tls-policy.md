# Require explicit remote PostgreSQL TLS policy

* Status: proposed
* Date: 2026-10-13

## Context and Problem Statement

The DB-8 audit requires verified TLS for non-loopback PostgreSQL destinations
and rejection of a remote connection without a supplied TLS mode. The existing
admission guard already checked all effective host and host-address entries and
rejected service indirection. However, its TLS-mode check accepted an omitted or
empty mode when the parent environment supplied a secure libpq default.

The minimal federation-worker environment deliberately forwards only `PATH`.
A connection policy accepted only because of a parent default is therefore not
self-contained when passed through the existing private credential descriptor
or reopened in another process. How should remote TLS admission remain
consistent without expanding worker environment access?

## Decision Drivers

* Preserve the audit's explicit missing-mode refusal and existing strict TLS guard.
* Preserve the minimal worker environment and descriptor-bound credential readers.
* Keep local Unix-socket and loopback deployments compatible.
* Do not change role separation, stored data, binary bindings or transaction semantics.

## Considered Options

* Require the parsed connection options themselves to select the verified TLS mode.
* Continue accepting effective environment defaults and forward libpq variables to workers.
* Add an insecure remote opt-out or resolve service-file indirection.

## Decision Outcome

Chosen option: require explicit `sslmode` with the value `verify-full` for a
non-local destination. An omitted or empty supplied value cannot satisfy this
requirement through `PGSSLMODE`. Every effective `host` and `hostaddr` entry
still participates in the existing local classification. This change adds no
insecure remote opt-out and retains rejection of service indirection.

The opener retains disabled database-name expansion and its forced disabling
of preferential GSS encryption. Secret-file and inherited-descriptor readers,
role handling, connection ownership and persisted formats are unchanged.
Certificate trust remains a deployment obligation: configure the trust source
for each process instead of depending on a parent-only environment variable.
Do not weaken the worker sandbox to conceal inaccessible certificate files.

### Positive Consequences

* Main and workers do not disagree about admission merely because a TLS-mode
  default was inherited by only one process.
* The new regression exercises URI and keyword formats, explicit-mode controls,
  omitted and empty modes, weaker modes, local exemptions and exact environment
  restoration without making a network connection.

### Negative Consequences

* Remote deployments relying only on `PGSSLMODE` must place the mode in their
  existing private connection-options file; no new configuration key is added.
* This does not resolve certificate-file accessibility in the worker sandbox.

## Verification and Scope

Against unchanged production, the new scenario built successfully and failed
4 of 28 assertions: omitted and empty explicit modes in both formats. Both
verified-mode controls and the setup/local/restoration checks passed. After
repair, the scenario passes 28 assertions / 1 case, all DB-8 unit checks pass
48 / 2, related DB-9 checks pass 6 / 1 and database units pass 18363 / 174.
The earlier DB-8/DB-9 guard RED/GREEN logs are preserved separately and are
historical evidence, not acceptance of this addition.

Independent source review passed with no security or logic findings. Parent
inspection bound the reviewed files to executed GREEN and verified preservation
of the preexisting untracked fixture and neighboring production changes against
the accepted pre-repair source checksums. The fresh combined checkpoint passed
56 OK targets, all return codes zero and no failures/timeouts, with 135 unchanged
snapshotted files including all 27 focused sources. The source freeze ended
after that acceptance. Normal DB-6
integration compatibility passes 2733 / 15. Both isolated PostgreSQL admission
modes pass 178 / 2 with verified shutdown and owned-fixture removal. Unit and
integration manifests match the same 27 current sources; both live database
manifests match their corresponding source subset. A successful TLS handshake, certificate and
hostname failure behavior, worker certificate access, native Windows execution
and whole DB-8/release acceptance are not established by these unit tests.

## Links

* [Database persistence](../database-persistence.md)
* [User manual](../user-manual.md)
* [PostgreSQL 16 connection parameters](https://www.postgresql.org/docs/16/libpq-connect.html)
* [PostgreSQL 16 TLS support](https://www.postgresql.org/docs/16/libpq-ssl.html)
