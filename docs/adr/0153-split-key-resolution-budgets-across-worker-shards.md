# Split the key-resolution budgets across federation worker shards

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding FED-10 (resolving sender keys for relayed PDUs
bypasses the key-resolution admission budget). Follows ADR-0132 to ADR-0135, which put every
network-capable key resolution behind the budgets.

## Context and Problem Statement

Network key resolution is admitted against `security.federation.key_resolution_max_in_flight` (16 in
flight per process) and `key_resolution_per_ip_rate` (30 per source IP per minute). Each federation
worker shard is a separate process with its own copy of both, so `federation.worker.shards` workers
allowed that many times the configured outbound key fetches. How should the aggregate be bounded?

## Considered Options

* **Give each worker shard its share: the configured limit divided by the shard count, rounded down,
  at least 1 (chosen).**
* One budget held by main, asked over IPC before every network fetch. Rejected: exact, but it adds an IPC
  round trip and a new frame type to every resolution, and a worker that cannot reach main could not
  resolve at all.
* Keep per-shard budgets and document the multiplier. Rejected: the configured value would not mean
  what it says.

## Decision Outcome

Chosen option: split by shard.

* `federation::shard_key_resolution_budget(config, shards)` divides `key_resolution_max_in_flight` and the
  per-IP rate's `max_requests`; every other field is unchanged.
* `start_runtime` applies it with `RuntimeStartOptions::key_resolution_shards`; the worker passes
  `federation.worker.shards`, and main leaves it at 1, keeping the whole budget for its own
  re-verification of relayed PDUs (ADR-0134).

### Negative Consequences

* A busy shard cannot borrow an idle shard's share.
* With more shards than a limit, each shard still gets 1, so the total is the shard count.
* Main's own budget is separate, so main and the workers together may resolve up to twice the
  configured limits.
