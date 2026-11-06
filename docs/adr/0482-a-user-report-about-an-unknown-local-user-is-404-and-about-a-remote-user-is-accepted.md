# A user report about an unknown local user is 404, and about a remote user is accepted

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`POST /users/{userId}/report` (v1.14): a `404` tells the reporter whether a user exists, and the spec lets a server
answer `200` regardless to hide that, or add a random delay.

## Decision Outcome

* A local user ID no account holds is `404 M_NOT_FOUND`; nothing is stored. `GET /profile/{userId}` is
  unauthenticated and already answers `404` for the same user, so the report endpoint adds no information, and the
  spec names the `404`.
* A user of another server is accepted with `200` without a lookup: this server cannot tell, and a report about a
  remote user is useful to an administrator who may then block that server or user.
* One audit row per reporter and reported user (`trust_safety.account.accept_report`), as the event report does a row
  per reporter and event; a repeat is acknowledged without another row, and the listing is capped
  (`max_safety_report_rows`). The free-text `reason` is validated but not stored, as for event reports.
* Rate-limited by the ordinary per-user and per-address buckets (the spec says "Rate-limited: Yes"). No random delay:
  the existence of a local user is not hidden, so there is nothing to blur.

Rejected: `200` for every unknown ID (hides nothing the profile endpoint shows, and the spec's `404` is clearer for
clients); storing a report for an ID with no account (an unbounded set of junk targets).
