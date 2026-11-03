# An IPC response that cannot be sent fails its requester at once

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-23 (`fed.send-join-acceptor-global-state-scan-and-unbounded-response-under-mutex`)

## Context and Problem Statement

`IpcChannel::send_response` refused a body over the frame cap by logging a warning and returning. The requester that sent
the matching `send_request` was waiting for exactly that frame and held its thread until its timeout: 60 s in a worker's
relay pool, 130 s for the main process's HTTP worker. `src/ipc/AGENTS.md` rule 4 says an oversize frame fails the send and
is never silently dropped, but a failed send that tells nobody is a drop for the peer. How is the requester told?

## Decision Drivers

* The requester must be released at once, with no answer, as a timeout would release it.
* The notice must itself fit in a frame whatever the cap is.
* One oversize answer must not end the channel, which carries every other request.
* Callers must not all need changing: they already handle "no response".

## Considered Options

* Send a small reply frame carrying the reserved member `ipc_error`, which the reader turns into "no response" for the waiter
* Mark the channel unhealthy
* Make `send_response` return a status the handler has to act on
* Leave the wait to the timeout

## Decision Outcome

Chosen option: "a small reply frame with `ipc_error`". In place of the oversize body `send_response` sends
`{"ipc_error":"response_too_large"}` under the request's `reply_to`; `reader_loop` completes the pending entry with no
response, so `send_request` returns `nullopt` exactly as for a timeout, and the existing callers answer 503. The oversize
body is still logged with its type and size. The member name is reserved: no frame body uses it.

### Positive Consequences

* A doomed answer costs the requester no timeout, and a thread is not pinned for 60 to 130 s.
* The channel stays up; every other request is unaffected.

### Negative Consequences

* The requester cannot tell the notice from a timeout. The reason is in the log of the process that dropped the body.

## Pros and Cons of the Options

### Mark the channel unhealthy

* Bad, because one large answer would end the worker's supervision and every other in-flight request on the channel.

### Make `send_response` return a status

* Good, because it is explicit.
* Bad, because the dispatch handlers send from pool threads that have nothing to do with the failure but log it; the peer is
  the one that has to be told.

## Links

* Related: [ADR-0322](0322-an-authenticated-frame-whose-payload-does-not-parse-fails-one-request.md) · [ADR-0366](0366-a-send-join-is-refused-before-it-is-stored-when-its-answer-cannot-be-delivered.md)
