# Default media quotas and a single in-memory blob copy

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-29

## Context and Problem Statement

Media repository capacity keys (`security.media.max_total_size`,
`max_size_per_user`, `max_records`) defaulted to empty strings that parsed as
zero, so an unconfigured server accepted an unlimited number of records and
bytes. In addition, after the runtime repository was hydrated from
`PersistentStore`, both `repository.blobs` and `store.media_blobs` held a copy of
the same blob bytes, doubling in-memory media memory (security audit finding
MED-6).

## Decision Drivers

* A freshly installed server must have safe operational defaults.
* Operators who need unbounded behaviour must opt in explicitly.
* Blob bytes should exist in at most one in-memory copy after hydration.

## Considered Options

1. **Keep unlimited defaults and document the risk.** Rejected: the audit showed
   that the consequence of unlimited defaults is not obvious to operators and
   has caused OOM conditions in similar deployments.
2. **Default to large but finite limits and preserve the explicit zero opt-out.**
   Accepted: it bounds an unconfigured server while retaining compatibility with
   operators who deliberately set `0`.
3. **Share a single `std::shared_ptr<std::string>` between persistent store and
   runtime repository.** Rejected: it complicates lifetime reasoning and the
   persistent store only needs the metadata after persistence. Moving the bytes
   and clearing the persistent copy is simpler.

## Decision Outcome

Chosen option: "non-zero defaults (`1GiB` total, `10MiB` per user, `100000`
records), and move blob bytes from `PersistentStore` into the runtime repository
during hydration, then clear the persistent copy", because it bounds the default
memory footprint and removes the duplicate in-memory copy without introducing
shared ownership.

### Positive Consequences

* An unconfigured server cannot be OOM-killed by unbounded local uploads or a
  large remote-media cache.
* Media blob bytes are held once in memory after startup.
* Explicit `0` limits still disable each cap for operators who want the old
  behaviour.

### Negative Consequences

* Servers that previously relied on unlimited defaults now enforce caps and may
  refuse uploads once they exceed them. This is the intended fail-closed
  behaviour and is documented in the default config.

## Links

* Security audit finding MED-6 in `docs/security-audit-report-2026-09-29.md`.
* Related capacity decision in [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md).
