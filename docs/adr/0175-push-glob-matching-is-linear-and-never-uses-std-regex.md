# Push glob matching is a hand-written linear matcher, never std::regex

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `sp01.push-glob-dp-allocation-per-character`

## Context and Problem Statement

Push rules evaluate `event_match` glob patterns ("Glob-style matching" in the spec's appendices)
against values the event's sender controls. They are evaluated for every local recipient of every
stored event, while the runtime lock is held. The whole-value matcher allocated a full
(value × pattern) table per match. The `content.body` matcher, which must match any substring
starting and ending at a word boundary, tried every pair of word boundaries and ran that table for
each, which is quadratic in the body before any per-pair cost.

## Decision Drivers

* The work done under `runtime.mutex` must not grow faster than linearly with input that one
  sender controls.
* The matcher must keep the spec's semantics exactly: `*` is zero or more characters, `?` is one,
  matching is case-insensitive, and `content.body` matches on word boundaries.

## Considered Options

* A hand-written matcher: exact comparison for a pattern without wildcards, a greedy matcher that
  backtracks to the last `*` for whole values, and a single-pass NFA simulation for word-boundary
  substrings
* Translate the glob to `std::regex` and use `regex_match` / `regex_search`
* Keep the dynamic-programming table but reuse one buffer

## Decision Outcome

Chosen option: "a hand-written matcher". Whole-value matching does no allocation and runs in
O(value × pattern) at worst (linear in practice). Word-boundary substring matching runs in one pass
over the body, holding the set of pattern positions reachable so far: O(body × pattern) time and
O(pattern) space. A seeded randomised test checks both against the old reference implementation,
so any later rewrite must keep the same answers.

### Positive Consequences

* A long message body no longer multiplies the per-recipient cost under the lock.
* No allocation per character.

### Negative Consequences

* The matcher is more code than a regex translation would be. The equivalence test is what keeps
  it honest.

## Pros and Cons of the Options

### std::regex

* Good, because it is short.
* Bad, because libstdc++'s `std::regex` backtracks: patterns with several stars can take
  exponential time and exhaust the stack (CWE-1333). It also allocates heavily, and compiling a
  pattern per evaluation repeats the cost this change removes.

### DP with a reused buffer

* Bad, because it removes the allocations but not the quadratic search over word-boundary pairs.

## Links

* Related: [ADR-0174](0174-sliding-sync-extension-room-lists-share-the-room-subscriptions-cap.md)
  (the same lock-held cost rule)
