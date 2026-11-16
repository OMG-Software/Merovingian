# The client-server dispatch boundary answers an escaped exception with a 500 and logs only its type

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: part 0 of the device authorization grant work (plan P11 in `docs/todos/oauth-2-0-api.md`).

Amended by [ADR-0810](0810-an-exception-escaping-one-of-the-server-s-own-pages-is-answered-with-a-fixed-error-page.md):
a request routed to one of the server's own HTML pages is answered with a fixed error page instead of the JSON 500.

## Context and Problem Statement

Handlers return errors as values, but a handler can still throw: `std::bad_alloc`, a standard library precondition, a
bug. Before this decision `handle_client_server_request` caught only `std::overflow_error` (the sync stream counter,
ADR-0315). Anything else left the dispatcher: on the main pool the transport's outer catch logged it and closed the
connection with no answer, the media fetch pool answered its own 500, and a sync poll swallowed it. The client saw a
dropped connection and retried, and the log line held whatever `what()` said. Where should an escaped exception be
answered, and what may the log say about it?

## Decision Drivers

* Every client-server request, from any pool, passes through `handle_client_server_request`.
* The runtime lock must be free after the exception, whatever the handler held.
* An exception's message can carry request data: a parser quoting its input, a path, a user ID, a value from a form.
  Under `/_merovingian/oauth2` and `/_merovingian/account` that can be a code, a token or a password field.
* The existing `std::overflow_error` answer ("sync stream counter exhausted") is relied on by tests and clients.

## Considered Options

* One `catch (...)` in `handle_client_server_request`, after the `std::overflow_error` catch, answering
  `500 M_UNKNOWN` with a fixed text and logging the method, the normalised route and the exception's type.
* The same, but logging `what()` as well.
* A catch in each transport call site (`HttpServer.cpp` main pool, sync pool, media fetch pool).

## Decision Outcome

Chosen option: one `catch (...)` at the dispatch boundary, logging the type and never the message.

* The answer is `dispatch_err(req, rt, 500U, "M_UNKNOWN", "internal server error")` with the request's CORS headers,
  as the overflow answer is built, so the connection carries on as it does after any other 500.
* The log is one `client_server` line at error level, `request.exception`, with `method`, `route`
  (`normalized_target`, so no ID and no query) and `type` (`core::current_exception_type_name`, the mangled type name
  from the C++ ABI, `unknown` where it is not available). It never includes `what()`.
* The lock: the handler's `RuntimeLock` and `RequestLockScope` are destroyed while the exception unwinds (a
  `RuntimeLockRelease` in scope re-acquires first and the guard then releases), so the catch takes the lock afresh
  for building the answer, as the overflow catch does, and releases it on return.
* `HomeserverRuntime::test_client_request_hook` is called with the request path after the rate limit, with the lock
  held, so a test can make one request throw (`tests/integration/test_request_exception_flow.cpp`). It is empty in
  production.
* `current_exception_type_name` moved to `core` (`CurrentException.hpp`) from the two copies in `net/ThreadPool.cpp`
  and `homeserver/HttpServer.cpp`, so the three users share one; `net` now links `core`.

### Positive Consequences

* A client gets an answer instead of a dropped connection, and the request is counted as completed.
* No request data reaches the log from an exception message.

### Negative Consequences

* Without the message, finding the throwing site needs the route and type, and then a reproduction. The thread pool's
  own catch-all still logs `what()`; it handles background tasks, not requests, and is unchanged.
* `std::bad_alloc` is answered too: the answer needs a little memory, and if building it throws, the exception leaves
  the dispatcher as before.

## Pros and Cons of the Options

### Logging `what()` as well

* Good, because the message often names the site.
* Bad, because the message can quote request data, and under the OAuth paths that is a secret.

### A catch in each transport call site

* Bad, because three copies drift, and a fourth caller (a test, the local router) gets none.

## Links

* Refines [ADR-0315](0315-a-sync-token-ahead-of-the-streams-is-an-initial-sync-and-the-counter-never-wraps.md)
