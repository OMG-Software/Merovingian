# Trust and safety

This capability note describes runtime-wired trust-and-safety behavior.

## Included now

- Registration policy checks in the runtime registration path.
- Account lock/suspension policy checks in the runtime login path.
- Room policy checks in the runtime room creation path.
- Media policy checks in the runtime download path and persisted moderation
  rules in the admin workflow.
- Federation request policy checks in the runtime federation path.
- Authenticated client event reporting through
  `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`.
- Admin report listing through
  `GET /_matrix/client/v3/admin/safety/reports`.
- Admin review actions through
  `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}`.
- Admin policy-rule management through
  `GET /_matrix/client/v3/admin/safety/policy_rules`,
  `PUT /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}`, and
  `DELETE /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}`.
- Remote policy-server transport through
  `security.trust_safety.policy_server_url` and the fail-closed
  `PolicyServerHook` path.
- Durable policy audit rows, admin action rows, and persisted `policy_rules`
  for report/review decisions.
- User-level ignore enforcement (Matrix v1.19 CS API §Ignoring Users):
  `merovingian::trust_safety::ignore_list` resolves a user's
  `m.ignored_user_list` account-data once per request and suppresses
  delivery of non-state events, room invites, and ephemeral typing/receipt
  entries from an ignored sender across `GET /sync`, MSC4186 sliding sync,
  `GET /messages`, `GET /context/{eventId}`, and push notification delivery.
  This is a **delivery-side, per-recipient filter, not a moderation
  action**: unlike the policy-engine controls above (which are operator- or
  admin-driven and block content server-wide), an ignore list is set by the
  ignoring user themselves and only changes what *that user's* clients are
  shown. See "Deliberately not included" below for what it does not protect
  against.

## Security posture

The runtime routes fail closed on missing authentication, missing admin
authorization, malformed report bodies, malformed review bodies, and unknown
review targets. When trust-safety transport is enabled, a missing or malformed
policy-server decision blocks the guarded workflow unless
`security.trust_safety.policy_server_allow_without_result=true`. Policy audit
rows store event type, actor, target, and reason code rather than free-form
event content.

## Deliberately not included

- Full Matrix v1.19 trust-and-safety conformance fixtures.
- Moderator queues beyond the current audit/admin action summaries.
- Multipart or streaming moderation inputs beyond the current request-local
  transport contract.

### What ignoring a user does NOT protect against

Per spec, ignoring is purely a client-delivery filter, not an access-control
mechanism, and Merovingian implements exactly that scope:

- **It does not prevent the ignored user from sending into a shared room.**
  Their events are still authorized, persisted, and included in the room's
  event graph and state resolution, exactly as if they were not ignored — an
  ignoring user with room-moderation power must still `/kick` or `/ban` to
  stop the sender, ignoring alone has no effect on that.
- **It does not hide history already delivered to the client.** The spec is
  explicit that the server "should not send events that were missed while the
  user was ignored" going the other way (on un-ignore) either — un-ignoring
  does not retroactively deliver what was suppressed; the client must start a
  fresh sync to see it. Merovingian never rewrites or deletes anything from
  the event graph to implement ignoring.
- **State events from an ignored sender are still delivered** (spec MUST), so
  ignoring a room's only power-level holder does not hide power-level,
  membership, or room-metadata changes they make.
- **It is not federation- or auth-visible.** An ignored sender's PDUs are
  verified, authorized, and accepted from federation exactly as any other
  sender's; the ignore list is consulted only at the point Merovingian
  serializes a response for the ignoring user's own clients.
- **It offers no protection against a determined abuser with multiple
  accounts** — ignoring is per-mxid, not per-person.
