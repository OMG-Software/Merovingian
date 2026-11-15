# Main builds make_leave and make_knock templates while the worker's reload of the room is pending

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

Technical Story: Complement `TestFederationRoomsInvite/Parallel/Invited_user_can_reject_invite_over_federation_several_times`,
failed once in the full run at 33a5cb61 after passing four times.

## Context and Problem Statement

ADR-0748 has main serve a room's reads while a worker's reload of the room is `pending`, and keeps the room's writes on
the worker. It listed `state`, `state_ids`, `backfill`, `event_auth`, `timestamp_to_event` and `get_missing_events` as
the reads. `make_leave` and `make_knock` were left with the membership writes, so the worker kept building them from
its snapshot. `make_join` was not affected: the worker always has main build its template (ADR-0184).

A `make_leave` template names the user's current membership event in `auth_events`. In the failed run, hs1 invited a
user on hs2, the invite returned 200, and the user rejected it about 300 ms later. hs1's worker had not reloaded the
room yet. Its template left out the invite, so the leave was a self-leave with no prior membership. When hs2 sent it
back, main judged it against those auth events and refused it with 403 ("self-leave requires current membership of
invite, join, or knock"). hs2's client got 502. `make_knock` has the same window: its template names the knocking
user's current membership.

How should a leave or knock template be built while a reload is pending?

## Decision Drivers

* A template must not leave out a membership change this server has already committed and shown to its clients.
* Main can build every membership template itself: it does when no worker is configured, and its provider takes
  `runtime.mutex`.
* Requests for a room the worker holds should keep going through the sandboxed worker when its copy is current
  (ADR-0748, ADR-0756).

## Considered Options

* List GET `make_leave` and `make_knock` in `federation_worker_room_read_may_fallback_to_main`, so main builds them
  while a reload is pending and the worker builds them otherwise.
* Have the worker always hand `make_leave` and `make_knock` to main, as it does `make_join` (ADR-0184).
* Have the leaving server retry `send_leave` with a fresh `make_leave` after a 403.

## Decision Outcome

Chosen option: the first. Both endpoints are GETs that build a template from room state and change nothing, so they
are reads in ADR-0748's sense, and `federation_room_request_served_by_main` already sends such reads to main while a
reload is pending. A PUT to either path is not a route the spec defines and does not fall back. The worker's local
provider is unchanged and still builds both when its copy is current.

### Positive Consequences

* A remote user can reject an invite, or leave, the moment this server shows them the invite, and the template names
  the invite. The same holds for a knock template.
* No IPC frame or relay changes. Main receives only requests `FederationProxy` has already verified, as for the other
  pending reads.

### Negative Consequences

* In a busy room more leave and knock templates are built by main instead of the sandboxed worker. They come from
  verified origins, and main already builds them when no worker is configured.
* As for every ADR-0748 read, the fix holds only while `notify_room_changed` marks the room `pending` before a client
  can see the change. A path that commits a membership change without notifying the worker would reopen the window.

## Pros and Cons of the Options

### Always relay make_leave and make_knock to main

* Good, because the template could never be stale, whatever the reload state.
* Bad, because every leave and knock template would leave the sandbox, also when the worker's copy is current.
* Bad, because `membership_template_ingest` carries no endpoint. Main assumes `make_join`, so the frame would need a new
  field that main must validate.

### Retry send_leave after a 403

* Good, because it needs no change to request routing.
* Bad, because it fixes only this server as the leaving side. A remote homeserver that leaves through this server still
  gets the stale template.
* Bad, because it hides a stale answer instead of not giving one.

## Links

* Refines [ADR-0748](0748-main-serves-a-rooms-federation-reads-while-the-workers-reload-is-pending.md)
* Keeps [ADR-0184](0184-federation-workers-relay-make-join-to-main.md) for `make_join`
* Applies per shard copy as in
  [ADR-0758](0758-every-worker-shard-reloads-every-changed-room-and-main-tracks-each-shards-copy.md)
