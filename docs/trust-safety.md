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

## Security posture

The runtime routes fail closed on missing authentication, missing admin
authorization, malformed report bodies, malformed review bodies, and unknown
review targets. When trust-safety transport is enabled, a missing or malformed
policy-server decision blocks the guarded workflow unless
`security.trust_safety.policy_server_allow_without_result=true`. Policy audit
rows store event type, actor, target, and reason code rather than free-form
event content.

## Deliberately not included

- Full Matrix v1.18 trust-and-safety conformance fixtures.
- Moderator queues beyond the current audit/admin action summaries.
- Multipart or streaming moderation inputs beyond the current request-local
  transport contract.
