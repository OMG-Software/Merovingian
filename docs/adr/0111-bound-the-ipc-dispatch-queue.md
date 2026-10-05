# Bound the IPC dispatch queue

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-29

## Context and Problem Statement

`IpcChannel` reads IPC frames on a dedicated reader thread and posts them to a
`std::deque` consumed by a dispatch thread. The deque had no upper bound: a
compromised or misbehaving federation worker could produce frames faster than the
dispatch thread could consume them, exhausting the main process's memory
(security audit finding CRY-2).

## Decision Drivers

* Fail closed on resource exhaustion rather than letting the queue grow forever.
* Keep the queue large enough that normal federation traffic never hits the cap.
* Preserve auditability by counting dropped frames.

## Considered Options

1. **Unbounded queue with back-pressure on the reader thread.** Rejected: the
   reader thread must stay responsive to frame flow-control and should not block
   waiting for downstream handlers.
2. **Drop newest frame when the cap is reached.** Rejected: a burst of legitimate
   frames would evict the most recent work, which is often the response the
   worker is waiting for.
3. **Drop oldest frame when the cap is reached.** Accepted: it limits memory,
   keeps the reader unblocked, and the stalest frame is the least valuable.

## Decision Outcome

Chosen option: "drop oldest frame once a configurable cap is exceeded", because
it bounds memory while preserving reader responsiveness and minimizing the
chance of dropping the frame the other side is currently waiting on.

### Positive Consequences

* Main's memory is no longer linear in a rogue worker's output rate.
* Drops are observable through the metrics counter.

### Negative Consequences

* A very slow handler can cause legitimate frames to be dropped. The queue cap
  is sized for peak expected concurrency; operators can raise it if needed.

## Links

* Security audit finding CRY-2 in `docs/security-audit-report-2026-09-29.md`.
* Supersedes the queue half of [ADR-0027](0027-bound-the-connection-queue-but-not-the-ipc-queue.md).
