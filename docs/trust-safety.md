# Trust and safety

This capability note describes runtime-wired trust-and-safety behavior.

## Included now

- Registration policy checks in the runtime registration path.
- Account lock/suspension policy checks in the runtime login path.
- Room policy checks in the runtime room creation path.
- Media policy checks in the runtime upload path.
- Federation request policy checks in the runtime federation path.
- Authenticated client event reporting through
  `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`.
- Admin report listing through
  `GET /_matrix/client/v3/admin/safety/reports`.
- Admin review actions through
  `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}`.
- Durable policy audit rows and admin action rows for report/review decisions.

## Security posture

The runtime routes fail closed on missing authentication, missing admin
authorization, malformed report bodies, malformed review bodies, and unknown
review targets. Policy audit rows store event type, actor, target, and reason
code rather than free-form event content.

## Deliberately not included

- Policy server network transport.
- Persistent policy-rule management endpoints.
- Full Matrix v1.18 trust-and-safety conformance fixtures.
- Moderator queues beyond the current audit/admin action summaries.
