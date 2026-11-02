# A membership template offers the room's stored forward extremities, and none is offered without them

* Status: accepted
* Date: 2026-11-02

Technical Story: security audit run-2 F-06, `make_join` offered rejected events and passed the 20 `prev_events` limit

## Context and Problem Statement

`membership_template_provider` built `prev_events` from its own scan: every stored row in the room that no other row
cites, whatever its status. A server outside the room can have rows stored as rejected, and nothing ever cites those.
With 21 of them the template passed the room version's limit of 20, and the send_join built from it was refused, so
no server could join through this one. A rejected row citing the tip also removed the tip from the template.

The spec requires that a rejected event is not a prev event of a generated event, and sets the limit. It does not say
what a resident answers when it holds no tip for a room it knows.

## Considered Options

* Use `forward_extremities_for_new_event`, the selection local events use
* Keep the scan and add a status filter and a cap
* For a room with no tips, answer 404 from `make_join`, `make_leave` and `make_knock`
* For a room with no tips, keep offering a template with empty `prev_events`

## Decision Outcome

Chosen option: "Use `forward_extremities_for_new_event`", because local events and templates then cannot disagree
about what a tip is. Filtering the scan would leave a second definition of a tip to keep in step. The federation worker's load profile already includes
`forward_extremities`, so `make_leave` and `make_knock` read it from the worker's snapshot.

With no tips, the provider offers no template, which the endpoint answers as 404 `M_NOT_FOUND`, the answer it already
gives for a room it cannot serve. A template with empty `prev_events` would detach the joiner's event from the room's
graph.

### Positive Consequences

* A server outside a room cannot stop others joining it through this server.
* A template's depth comes from accepted events, so a rejected row at the depth limit cannot set it.

### Negative Consequences

* A test or tool that stores rows directly has to update `forward_extremities` before asking for a template.
