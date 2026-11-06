# Statistics counters use the default memory order

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

Technical Story: SonarQube Cloud rule `cpp:S8417` on `homeserver::HttpServeStats` and `database::ExaminedRows`.

## Context and Problem Statement

`HttpServeStats` and `ExaminedRows` are counters held in `std::atomic` members. Their operations passed
`std::memory_order_relaxed` explicitly. A counter needs no ordering against other memory, so relaxed is correct, but
every site that names an ordering asks the reader to prove that again. Which ordering should these two types use?

## Considered Options

* Keep `std::memory_order_relaxed` at each site.
* Use the default (sequentially consistent) ordering.

## Decision Outcome

Chosen option: "Use the default ordering", because the counters are read once per operation, never per row, so the
stronger ordering has no measurable cost and removes a per-site proof burden. The behaviour of both types is unchanged.

This decision covers `HttpServeStats` and `ExaminedRows` only. It does not require changing other relaxed sites
elsewhere in the codebase, each of which keeps whatever ordering it was justified with.

## Pros and Cons of the Options

### Keep relaxed

* Good, because it is correct for counters.
* Bad, because it is a proof burden at every site with no measured benefit at once-per-operation frequency.

### Default ordering

* Good, because it needs no argument about what else it must order against.
* Bad, because on weakly ordered hardware each operation is marginally more expensive, which these frequencies hide.
