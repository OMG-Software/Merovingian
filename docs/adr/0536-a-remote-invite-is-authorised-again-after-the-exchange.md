# A remote invite is authorised again after the exchange

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

An invite to a user of another server is composed (and so authorised) under `runtime.mutex`, then offered to the
invitee's server with the mutex released for up to the offer deadline. When the mutex is back, only the room's
existence and the inviter's membership were rechecked, so an inviter banned or demoted during the exchange still
had the invite stored and sent.

## Considered Options

* Recheck membership only (previous behaviour).
* Run the room's auth rules for the composed event against the current state (`composed_event_is_still_authorised`).
* Hold the mutex across the exchange.

## Decision Outcome

Chosen option: run the auth rules again against current state after the mutex is re-acquired and before the invite
is queued or stored; a failure is `403 M_FORBIDDEN` with nothing stored. The mutex is never held across the network
call (coding rules), and a membership check alone does not see a power-level change or a ban.
