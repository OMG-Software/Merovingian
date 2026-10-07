# Default media quotas and a single in-memory blob copy

* Status: accepted; since [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md)
  media bytes are no longer held in memory, so `max_total_size` limits stored bytes, not
  memory. The defaults are unchanged.
* Deciders: James Chapman
* Date: 2026-10-06

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

Chosen option: "non-zero defaults (`2GiB` total, `256MiB` per user, `100000`
records), remote media exempt from the per-user quota, and blob bytes held only
by the runtime repository", because it bounds the default memory footprint and
removes the duplicate in-memory copy without introducing shared ownership.

The numbers follow from where media lives. Every blob is held in memory and is
loaded from the database at startup, so `max_total_size` is a memory budget, not
a disk quota; the default suits a small host, and operators with more memory
raise it. `max_size_per_user` must stay at or above `max_upload_size`
(`50MiB`), or a single legitimate upload is refused: the first implementation
shipped `10MiB` per user and failed that. Remote media is stored under one
`@remote-media:<origin>` owner per origin, so charging it to the per-user quota
would refuse every further file from a busy origin after its first few; it is
bounded by `max_total_size` and `max_records` instead.

The persistent store keeps only blob metadata: hydration moves the bytes into the
runtime repository, and `store_media_blob` stores a metadata-only row once the
bytes have been written to the database.

### Positive Consequences

* An unconfigured server cannot be OOM-killed by unbounded local uploads or a
  large remote-media cache.
* Media blob bytes are held once in memory after startup.
* Explicit `0` limits still disable each cap for operators who want the old
  behaviour.

### Negative Consequences

* Servers that previously relied on unlimited defaults now enforce caps and may
  refuse uploads once they exceed them (`507 M_LIMIT_EXCEEDED`). This is the
  intended fail-closed behaviour; the defaults and their memory meaning are in
  `docs/user-manual.md` and `config/merovingian.conf.example`.
* The defaults were chosen by the project owner on 2026-10-06 over larger caps,
  accepting earlier 507s on busy servers in exchange for a safe footprint on
  small hosts.

## Links

* Security audit finding MED-6 in `docs/security-audit-report-2026-09-29.md`.
* Related capacity decision in [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md).
