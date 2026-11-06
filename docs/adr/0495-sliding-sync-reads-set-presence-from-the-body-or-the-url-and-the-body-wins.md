# Sliding sync reads `set_presence` from the body or the URL, and the body wins

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

Presence is "online" while a client polls (CS API, `GET /sync` `set_presence`). Sliding sync never applied it, so a user
whose client used only sliding sync had nothing marking them active, and the idle sweep (ADR-0492) would set them
`unavailable` while they were using the account. MSC4186 (`erikj/sss` branch, `proposals/4186-simplified-sliding-sync.md`)
lists `set_presence` in the request body table: "Same as in `/v3/sync`, controls whether the client is automatically marked
as online by polling this API". Its changelog calls it a URL parameter. MSC4186 is not part of Matrix v1.19.

## Decision Outcome

The sliding sync handler reads `set_presence` from the body and, when the body has none, from the URL query. The body wins
because the proposal's request table puts it there, as it does `pos` and `timeout`. The value is judged as `/sync` judges it
(`parse_sync_presence_mode`): omitted marks the user online, `offline` changes nothing, `unavailable` marks them idle, and
anything else, including a body value that is not a string, is `400 M_INVALID_PARAM` before the request does anything. A
change is applied with `apply_sync_presence` and told to other servers with `broadcast_presence_edu`, as `/sync` does, so a
poll that changes nothing costs no row, stream position or EDU.

* A rejected alternative is reading only the URL, which is what the changelog says; the request table is the normative
  part and clients that follow it (Element X puts `pos` and `timeout` in the body) would then never mark themselves online.
