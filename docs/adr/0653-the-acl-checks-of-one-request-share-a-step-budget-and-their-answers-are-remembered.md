# The ACL checks of one request share a step budget, and their answers are remembered

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C38 (the server ACL step budget was per check, not per request).

## Context and Problem Statement

ADR-0640 bounded one server ACL check to 1,000,000 glob steps. The `m.receipt` EDU sink, which names up to 512 rooms,
runs one check for each room it holds a local member in, all under `runtime.mutex`; a remote server that administers a
few such rooms and writes each ACL to cost the whole budget makes one EDU cost hundreds of millions of steps, and the
per-origin EDU rate prices an EDU as one.

## Decision Drivers

* The work one inbound request causes under the lock must be bounded by one budget, whatever it names.
* Under the budget the answer must not change: an ACL is a security control, and an unevaluated pattern is a refusal.
* A cache must be synchronised and bounded (ADR-0525), and a redaction rewrites an ACL event under the same ID.

## Considered Options

* A `ServerAclBudget` (1,000,000 steps) shared by every check of one EDU or relayed frame, a per-check limit lowered to
  100,000, and a cache of answers per (ACL event version, lower-cased host).
* Only lower the per-check limit.
* Only cache the answers.

## Decision Outcome

Chosen option: the first.

* `room_server_acl_allows(store, room, server, budget)` and `evaluate_server_acl(server, acl, budget)` spend from the
  caller's `ServerAclBudget`. A check spends at most `min(server_acl_max_glob_steps, budget.steps_left)`; when the
  budget is gone a check that still needs a step answers deny with the rule `acl_budget`, like an over-budget check.
  The receipt sink makes one budget per EDU; the worker-relay re-check makes one per relayed frame. The overloads
  without a budget give each check its own, for callers that make one check per request (`/event`, the typing sink).
* `server_acl_max_glob_steps` drops from 1,000,000 to 100,000: 4096 patterns against a 24-character name is about that,
  and an ACL beyond it has no honest use. The per-request budget keeps the old 1,000,000.
* The answer for an ACL event version (event ID, JSON size and JSON hash, the key of the parse cache) and a lower-cased,
  port-stripped host is kept in a 4096-entry cache with its own mutex that is emptied when full. A refusal for running out
  of a budget that was smaller than the per-check limit says nothing about the ACL and is not kept; every other answer is.

### Negative Consequences

* A request that names more rooms than its budget pays for has its later rooms refused (the receipt of an honest
  origin is dropped for those rooms, not the whole EDU). 1,000,000 steps cover thousands of ordinary ACLs.
* The parse cache still holds 256 entries, so a request over more than 256 distinct ACL events can reparse; that cost is
  bounded by the per-EDU room cap and is left for a later change.

## Links

* Refines ADR-0640. Uses ADR-0525.
