# Every federation error is a standard JSON error, and /send answers every PDU

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestBannedUserCannotSendJoin`,
`TestOutboundFederationIgnoresMissingEventWithBadJSONForRoomVersion6`)

## Context and Problem Statement

Federation handlers returned plain-text error bodies (a banned user's `send_join` answered
`event auth denied ...`), while the spec's standard error response is a JSON object with `errcode` and
`error`. And `PUT /send` listed only the PDUs that failed, while the spec says `pdus` holds "The PDUs
from the original transaction", with `{}` for one that was processed.

## Decision Outcome

* `handle_inbound_federation_request` wraps any non-JSON error body as `{errcode, error}`, the errcode
  following the status (400 `M_INVALID_PARAM`, 403 `M_FORBIDDEN`, 404 `M_NOT_FOUND`, ...). A handler
  that knows a more exact errcode builds its own `matrix_error`, which is left alone.
* `/send` lists every PDU: `{}` when handled (including one retained for a retry) and `{"error": ...}`
  otherwise, also for a transaction answered as a duplicate.
* A future handler must not return a bare string body, and "omit the successes" must not come back.
