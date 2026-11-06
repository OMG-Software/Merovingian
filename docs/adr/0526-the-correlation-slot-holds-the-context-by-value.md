# The correlation slot holds the context by value

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`observability::CorrelationScope` publishes a request's correlation context on the calling thread, and
`current_correlation_context()` reads it for log lines and outbound `traceparent` headers. The thread's slot held a
pointer. At first it pointed at the caller's context object, which CodeQL flags as a stack address stored in non-local
memory (`cpp/stack-address-escape`). The first fix made the scope own a copy and publish a pointer to that copy. CodeQL
flags that too, because the scope is itself a local variable, so `this` is a stack address. Both forms are correct while
scopes nest properly, but they rest on an argument the code cannot state, and CodeQL cannot follow it. What should the
slot hold?

## Considered Options

* Keep the pointer to the scope's own copy and dismiss the alert.
* Allocate the scope's copy on the heap and publish a pointer to it.
* Make the slot hold the context by value: a scope moves its context in and keeps the one it displaced.

## Decision Outcome

Chosen option: "Make the slot hold the context by value". The slot is a `thread_local std::optional<CorrelationContext>`.
Opening a scope exchanges its context into the slot and keeps the previous value. Closing it moves that value back. No
address of a scope, or of anything on a stack, is stored anywhere. `current_correlation_context()` returns a pointer
into the thread's own slot, which outlives every scope on the thread.

Do not go back to publishing a pointer. A pointer to a scope or to a caller's object is a stack address, whatever owns
the object.

### Positive Consequences

* The alert is gone because the code changed, not because it was dismissed.
* A reader cannot see a destroyed context, whatever the caller does with its own object.

### Negative Consequences

* Opening a scope moves three strings into the slot, and closing it moves them back. That is a few pointer swaps, with
  no allocation.
* A pointer from `current_correlation_context()` points at the slot, so it shows whatever context a scope opened or
  closed later on that thread put there. Callers read it at once; none keeps it.

## Pros and Cons of the Options

### Keep the pointer and dismiss the alert

* Good, because nothing changes.
* Bad, because the safety rests on scopes nesting, which the type cannot enforce and a reader has to take on trust.

### Allocate the copy on the heap

* Good, because the published address is not on a stack.
* Bad, because every request pays for an allocation to hold three strings the slot could hold itself.

## Links

* Refines the `CorrelationScope` change in 0.12.79 (`CHANGELOG.md`)
