# The supervisor restarts a live worker whose main-side channel has failed

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-08

## Context and Problem Statement

`WorkerSupervisor::supervisor_loop` restarted a worker only when `waitpid` reported that it had exited. Main's side
of the channel can fail while the worker lives: the reader hits a failed read or a failed authentication, the dispatch
queue count or byte cap is exceeded, or a request handler throws. `healthy()` then reports false, so
`WorkerPool::handle` answers 503 for every request routed to the shard, `notify_room_changed` drops `room_sync`, and
main's own outbound federation through the shard fails. The worker does not notice (its own side of the socket is
healthy), so nothing replaces it until main is restarted by hand.

[ADR-0078](0078-the-federation-worker-never-signs.md) declined to tear down a channel on an unexpected frame from a
worker, so that a compromised worker could not churn restarts. That concerns a frame type main does not serve. A
channel that has already died is not a choice about a frame: the shard is down either way.

## Considered Options

* The supervisor kills a live worker whose channel is unhealthy and restarts it through the existing path
* Shut the socket down from the failing reader, so the worker's own watcher exits
* Do nothing and rely on the operator

## Decision Outcome

Chosen option: "the supervisor kills it and restarts it". In the loop's poll, when the worker has not exited and
`channel_snapshot()` reports an unhealthy channel, the supervisor sends SIGKILL, reaps the worker, and continues into
the code that handles an exit: the old channel is stopped and the worker is respawned after the existing backoff
(1 s doubling to 30 s, reset after 30 s of health). A restart caused this way is counted and delayed exactly like a
crash, so a peer that repeatedly breaks its channel gets a bounded restart rate, not a faster one.

SIGKILL rather than a graceful stop because the worker has nothing to finish: its requests come from main through the
dead channel and its answers could not be delivered. Having the reader shut the socket down was rejected because
it covers only the failure the reader sees (a handler exception or a queue overflow is not a read failure) and leaves
the decision to restart in the thread that is failing, where the supervisor's backoff does not apply.

### Positive Consequences

* A main-side channel failure heals itself in about the backoff, whatever caused it.

### Negative Consequences

* A worker that makes its own channel fail repeatedly (a compromised one) causes restarts at the backoff rate. It
  could already do that by exiting.

## Links

* Refines [ADR-0078](0078-the-federation-worker-never-signs.md)
* Related to [ADR-0322](0322-an-authenticated-frame-whose-payload-does-not-parse-fails-one-request.md)
