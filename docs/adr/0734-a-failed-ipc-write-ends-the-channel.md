# A failed IPC write ends the channel

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C44,
`F-resource-exhaustion.sqlite-worker.read-lock-held-by-compromised-worker-fails-every-main-write`, step 1 of
[ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md).

## Context and Problem Statement

`IpcChannel::write_frame` encrypts a frame with the channel's secretstream state and writes it. `send_response` ignored
the result. A write that failed part way (the socket's 30 s send timeout, a peer that stopped reading, `EPIPE`) left
the stream one frame ahead of the peer's decryptor, so every later frame failed authentication there, while this side
still reported `healthy()`. The supervisor replaces a worker only when its channel is unhealthy (ADR-0323), so a worker
whose channel broke this way stayed up and served nothing, and `write_mu_` was held for the whole timeout on each
attempt. The worker's data now arrives as large responses from main (ADR-0733), which makes a stalled write likely
enough to matter. What should a failed write do?

## Considered Options

* A failure after encryption marks the channel unhealthy and shuts the socket down
* Retry the write
* Leave it to the peer to notice the broken stream

## Decision Outcome

Chosen option: the first. `write_frame` calls `end_after_failed_write` when encryption or either `send` fails: the
channel is marked unhealthy and `shutdown(SHUT_RDWR)` wakes the reader, which releases every waiting `send_request`.
A frame over the cap or a failed allocation is refused before encryption and changes nothing, so it keeps the channel,
as ADR-0368 requires. All three send paths go through `write_frame`, so `send_response`, `send_request` and
`send_notification` share the rule.

### Negative Consequences

* One slow write ends a worker's channel; the supervisor restarts the worker after its back-off. That is the intent:
  the channel cannot carry another frame anyway.

## Pros and Cons of the Options

### Retry the write

* Bad, because a frame written in part cannot be resumed or resent: the cipher state has moved on.

### Leave it to the peer

* Bad, because the side that failed keeps reporting healthy, so main's supervisor never replaces its worker, and a
  worker never learns that main cannot read it.

## Links

* Refines [ADR-0323](0323-the-supervisor-restarts-a-worker-whose-main-side-channel-failed.md)
* Related [ADR-0368](0368-an-ipc-response-that-cannot-be-sent-fails-its-requester-at-once.md)
