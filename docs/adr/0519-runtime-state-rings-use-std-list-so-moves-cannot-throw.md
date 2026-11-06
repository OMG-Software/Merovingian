# Runtime state rings use std::list so moves cannot throw

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

Supersedes [ADR-0268](0268-runtime-state-structs-keep-their-implicit-throwing-moves.md).

Technical Story: SonarQube Cloud rule `cpp:S5018` on `federation::FederationRuntimeState`,
`homeserver::LocalDatabase` and `homeserver::AppserviceEphemeralQueue`.

## Context and Problem Statement

[ADR-0268](0268-runtime-state-structs-keep-their-implicit-throwing-moves.md) kept the implicit moves of these three
aggregates and marked the findings as false positives. They are not nothrow-move-constructible under libstdc++ because
`std::deque`'s move constructor allocates an empty block map for the moved-from object. The owner has decided to remove
the cause instead. Which container should hold the capped FIFO rings?

## Considered Options

* Keep the implicit moves and mark the findings as false positives (ADR-0268).
* Declare `noexcept = default` move operations on each struct.
* Remove `noexcept` from `HomeserverRuntime`'s move operations.
* Replace the `std::deque` members with `std::list`.
* Replace them with a vector-backed ring.

## Decision Outcome

Chosen option: "Replace the `std::deque` members with `std::list`", because it is a drop-in for every operation the
rings use (`push_back`, `pop_front`, `front`, `back`, `size`, `empty`, forward and reverse iteration, `std::ranges`
algorithms, `std::erase_if`), its move constructor and move assignment are `noexcept` under both libstdc++ and libc++,
and `pop_front` frees the evicted element at once.

The members converted are `FederationRuntimeState::{accepted_transactions, audit_events, key_resolution_buckets,
key_resolution_failures, bad_signature_buckets}`, `LocalDatabase::audit_events`, `AppserviceEphemeralQueue::items` and
`PersistentStore::audit_log`. Each struct carries a `static_assert` that it is nothrow move constructible and
assignable, so a later member that breaks the guarantee fails the build.

A ring that needs random access (`operator[]`, iterator arithmetic, sorting) does not belong in a `std::list`; use a
different structure rather than `std::next` in a loop. `PersistentStore::captured_statements`, a test-only capture that
tests index by position, becomes a `std::vector` instead: its move is `noexcept`, it keeps positional access, and the
oldest entries are dropped with one range erase per commit, which is cheap for a capped test buffer.

### Negative Consequences

* One allocation per element, acceptable for rings that are capped and whose elements are heavy.
* Iteration is less cache friendly than a deque's blocks; none of these rings is walked on a hot path per row.

## Pros and Cons of the Options

### Keep the implicit moves

* Good, because nothing changes.
* Bad, because the finding stays, and a later `std::vector` of such a struct would silently copy.

### Declare `noexcept = default` move operations

* Bad, because a user-declared constructor ends aggregate status, and a `bad_alloc` during the move would then call
  `std::terminate`: a silenced warning with the same hazard.

### Remove `noexcept` from `HomeserverRuntime`'s move operations

* Bad, because nothing catches the exception, so the outcome is the same, and a throwing move assignment can leave a
  runtime half moved.

### `std::list`

* Good, because every operation the rings use exists, with the same complexity for those used.
* Good, because the moves cannot throw on either standard library.
* Good, because `pop_front` releases the evicted element immediately.
* Bad, because each element is its own allocation.

### A vector-backed ring

* Bad, because evicted elements stay alive until compaction, and it is new code to write, test and maintain.
