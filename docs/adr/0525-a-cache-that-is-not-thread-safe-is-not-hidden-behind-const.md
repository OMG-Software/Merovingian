# A cache that is not thread-safe is not hidden behind const

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`sync::UnreadEventClassifier` asked its three questions through `const` member functions, and
`homeserver::PushRuleUnreadClassifier` answered them from eight `mutable` caches it filled lazily. The type is built once
per request and is documented as unsafe to share between threads. SonarCloud flags a `mutable` field changed in a
`const` function without a lock (`cpp:S8379`), and `const` told a reader the call changed nothing.

## Considered Options

* Keep the `const` questions and guard the caches with a mutex.
* Make the questions non-`const` and drop `mutable`.

## Decision Outcome

Chosen option: "Make the questions non-`const`". A function that fills a cache changes the object, and an object that
is not safe to share needs no lock, only an honest signature. Callers hold the classifier by non-`const` reference.

The rule for future code: a `const` member function may change only members that are themselves synchronised (a mutex,
an atomic) or that it guards with the object's own mutex, as `homeserver::RoomPositionIndex` does (ADR-0521). A lazily
filled cache in a type that is not thread-safe is changed through non-`const` functions, never through `mutable`.

### Negative Consequences

* A caller cannot pass the classifier as a temporary or through a `const` reference.

## Pros and Cons of the Options

### Guard the caches with a mutex

* Good, because the signatures stay as they were.
* Bad, because it adds a lock to an object one thread uses, and keeps a `const` that is not true.
