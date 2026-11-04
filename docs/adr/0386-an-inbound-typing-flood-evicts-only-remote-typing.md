# An inbound typing flood evicts only remote typing

* Status: accepted
* Date: 2026-11-03

Technical Story: the typing table is one vector shared by this server's users and every remote user,
capped at `max_inbound_typing_entries`. A remote server filling it erased the oldest entry, which could be a
local user's, without telling that user's room.

## Context and Problem Statement

When a new remote typing entry arrives and the table is at its cap, which entry goes?

## Considered Options

* Evict the oldest entry, whoever's it is (the previous behaviour)
* Evict the oldest remote entry, and drop the new entry if there is none
* Keep a separate table, and a separate cap, for remote typing

## Decision Outcome

Chosen option: evict the oldest remote entry, and drop the new entry if the table holds none.

A local user's typing is the only typing this server vouches for, and a peer must not be able to clear it
(the same rule as the receipt cap, which never evicts a local user's receipt). Dropping the incoming entry when
every entry is local costs one remote indicator that would have expired in 60 seconds.

A separate table was not chosen because every reader of `typing_users` (sync, expiry, appservice delivery) would
need to change for no behaviour the single rule does not give.

The cap is no longer the bound on a non-member's typing: an EDU for a user who is not joined to the room, or from
a server the room's ACL denies, is ignored before it reaches the table (Server-Server API, "Typing
Notifications" and "Server Access Control Lists (ACLs)").

## Links

* Refines [ADR-0199](0199-typing-expires-on-a-periodic-job-with-a-ceiling-and-a-federation-timeout.md) only in what the cap evicts
