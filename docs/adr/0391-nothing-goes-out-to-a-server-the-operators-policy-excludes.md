# Nothing goes out to a server the operator's policy excludes

* Status: accepted
* Date: 2026-11-04

Technical Story: security audit run 2, finding F-69: `denied_servers` and `allowed_servers` were enforced
for inbound requests only, so this server still sent PDUs, EDUs, membership calls and media requests to a
server its operator had excluded.

## Context and Problem Statement

The operator's lists read as "have nothing to do with this server". Outbound traffic takes several routes:
the PDU fan-out, `perform_outbound_call` for make and send membership calls and key queries, the durable
dispatch worker for EDUs, and remote media fetches. A check at each caller would miss the next caller, and
rows already queued when the operator added a server would still be delivered after a restart, because
`security.federation.*` is `restart_required` and the queue survives it.

## Considered Options

* **Gate on the config lists at the delivery chokepoints, and drop queued rows on replay (chosen).**
* Also judge the admin federation rules outbound. Rejected: delivery threads must not wait on
  `runtime.mutex`, and a rule lookup needs it. Rules are for what comes in (ADR-0390); the lists are read
  without the lock because they cannot change while the server runs.
* Keep queued rows and refuse them at send time. Rejected: they would be retried forever for a destination
  that will never be allowed again until the operator changes the config and restarts.

## Decision Outcome

`perform_outbound_call`, the PDU fan-out in `room_service.cpp`, `dispatch_edu_to_server`,
`remote_media_refusal` and `DispatchWorkerConfig::destination_refusal` all ask `federation_server_policy`.
`DispatchWorker::enqueue` refuses a new row, and `replay_pending` deletes rows for an excluded destination.

What the caller sees follows from what it asked for, not from the policy. `sendToDevice` answers 200 and
sends nothing to that server, because one excluded recipient must not fail the others. Remote media from an
excluded server answers 404, as for any media this server has been told not to fetch (ADR-0080).

### Negative Consequences

* A server with federation disabled now also sends nothing through these paths, because
  `federation_server_policy` refuses every name in that state. That is the intended meaning of the setting.
* A client gets no signal that a to-device message to an excluded server went nowhere.

## Links

* Refines [ADR-0390](0390-the-operators-federation-policy-also-covers-the-server-that-wrote-an-event.md)
