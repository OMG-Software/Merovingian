# Runtime state structs keep their implicit, possibly throwing, moves

* Status: accepted
* Date: 2026-10-29

Technical Story: SonarQube Cloud rule `cpp:S5018` (3 open findings, triaged 2026-10-29)

## Context and Problem Statement

SonarQube Cloud asks for a `noexcept` move constructor on `homeserver::AppserviceEphemeralQueue`,
`homeserver::LocalDatabase` and `federation::FederationRuntimeState`. All three are aggregates
whose move constructor is implicit, and the implicit one is not `noexcept` because each holds a
`std::deque`: libstdc++'s `deque(deque&&)` allocates an empty block map for the moved-from
object, so it can throw `std::bad_alloc`. A probe compiled with the project's build flags confirms
`std::deque` is the only member that is not nothrow-move-constructible; libc++ (the BSD builds)
marks the deque move `noexcept`, so the findings exist only on the Linux build.

A throwing move matters where a container chooses between moving and copying with
`std::move_if_noexcept`, chiefly `std::vector` growth. None of these types is held that way:
`AppserviceEphemeralQueue` is a `std::map` value (nodes never relocate), and the other two are
built once and moved into the runtime. Should the structs be changed to satisfy the rule?

## Considered Options

* Keep the implicit moves and mark the findings as false positives
* Declare `noexcept = default` move operations on each struct
* Replace the `std::deque` members with a container whose move is `noexcept`

## Decision Outcome

Chosen option: "Keep the implicit moves and mark the findings as false positives", because nothing
in the code pays for the throwing move, and both alternatives cost more than the finding is worth.

A struct of this kind that is later stored in a `std::vector`, or whose move must be `noexcept`
for another reason, should revisit this: check `std::is_nothrow_move_constructible_v` under
libstdc++ first.

### Negative Consequences

* The three findings stay in SonarQube Cloud until they are marked as false positives there.

## Pros and Cons of the Options

### Declare `noexcept = default` move operations on each struct

* Good, because it silences the rule.
* Bad, because a user-declared constructor ends aggregate status, so each struct would also need
  explicit default, copy and assignment members.
* Bad, because a `bad_alloc` during a move would then call `std::terminate` instead of
  propagating, which trades a recoverable error for a crash with nothing gained.

### Replace the `std::deque` members with a container whose move is `noexcept`

* Good, because the implicit moves would become `noexcept` with no other change to the structs.
* Bad, because the deques are the FIFO-capped audit, replay-dedup and key-resolution rings, whose
  `pop_front` eviction they rely on; replacing them changes behaviour across federation and audit
  code to remove a warning with no runtime effect.
