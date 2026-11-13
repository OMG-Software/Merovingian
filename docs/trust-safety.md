# Trust and safety

This capability note describes runtime-wired trust-and-safety behavior.

## Included now

- Registration policy checks in the runtime registration path.
- Account lock/suspension enforcement: the request-path gate in `ClientServerRuntime.cpp` (`M_USER_LOCKED` on all but
  logout, `M_USER_SUSPENDED` outside the spec's allowlist) and the lock check in `/refresh` (`AuthService.cpp`). The
  engine's `evaluate_account_policy` and `evaluate_invite_policy` had no caller and were removed; there is no
  invite-scope policy.
- Invite permission (0.12.81, SS7, [ADR-0552](adr/0552-invite-permission-is-decided-where-account-data-is-held-and-createroom-drops-only-a-remote-block.md)).
  This is account data, not a policy-engine surface: a local user whose `m.invite_permission_config` has
  `default_action: "block"` is sent no invites. Every invite to them is refused with `403 M_INVITE_BLOCKED` and
  nothing is stored: federation `PUT /v1/invite` and `/v2/invite` (decided on main before signing), `POST /invite`,
  `PUT /state/m.room.member` with membership `invite`, and `POST /createRoom` (which creates nothing when a local
  invitee blocks). A remote server's `M_INVITE_BLOCKED` makes `POST /invite` answer the same, and in `createRoom`
  drops only that invite. Invites already stored are withheld from `/sync` and sliding sync while the block lasts
  (`src/homeserver/InvitePermission.cpp`).
- Room policy checks in the runtime room creation path.
- Media policy checks in the runtime client and federation download paths and
  persisted moderation rules in the admin workflow. Federation's production
  provider now invokes the same media decision before repository lookup or byte
  reads (MED-7, ADR-0144); a denied item yields 403 without media bytes
  or a successful multipart envelope. The existing media-surface policy-server
  hook and its configured unavailable-result policy are reused, not replaced by
  a separate federation-only rule evaluator. The new regression uses real
  SQLite, admin PUT/DELETE, genuine federation signatures and the production
  dispatcher; configured-unavailable-hook coverage has no injected callback.
  The bounded admission repair passes independent review and a fresh normal
  full suite (56 OK, all return codes zero, 1,026 unchanged frozen files).
  Live remote-hook responses and strict mid-request policy revocation are not
  claimed, nor is whole-audit or release acceptance. Media whose policy is `allow-after-scan` can be scanned by a local ClamAV
  daemon before it is admitted (G15, ADR-0565); see [media-repository.md](media-repository.md) and the user manual.
- Federation request policy checks in the runtime federation path. Main makes the decision, never a worker
  (F-21, ADR-0358): `FederationProxy::handle` applies the origin's scope-`federation` policy rule after the X-Matrix signature
  verifies and before any branch, including the forward to a worker (`403 M_FORBIDDEN`), and asks the policy server once,
  just before the forward, or in `handle_federation_http_request` for what main answers itself. A rule takes effect on the next request on either database backend, because a worker's store holds no
  rules (PostgreSQL) or a start-up snapshot (SQLite). The main-side relay handlers (`pdu_ingest`, `membership_ingest`,
  `invite_ingest`, `edu_ingest`) judge the local rule again, without the policy server, for a rule added while a request
  was in flight. A worker never judges a request
  (`HomeserverRuntime::federation_policy_decided_upstream`).
- Authenticated client event reporting through
  `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`. The reporter must be
  joined to the room and the event must be in it and visible to them under the
  room's history visibility, otherwise `404 M_NOT_FOUND` (spec: "The event was not
  found or you are not joined to the room where the event resides"). A repeat report
  of the same event by the same reporter is acknowledged without a second audit row
  (CSAZ-12, ADR-0127).
- User reporting through `POST /_matrix/client/v3/users/{userId}/report` (v1.14,
  ADR-0482): an unknown local user is 404, a user of another server is accepted,
  and one audit row (`trust_safety.account.accept_report`) is kept per reporter
  and reported user. The reason text is validated, not stored.
- A report costs no read of `audit_log` (C26, ADR-0686): the routes judge a repeat and a reporter's share from the
  in-memory `SafetyReportIndex`, filled at start-up from the report rows already stored. A reporter may file 20 reports
  a minute (per user) and 100 distinct reports a day; a further one is `429 M_LIMIT_EXCEEDED`, a repeat is still
  acknowledged. The listing below still reads the newest `max_safety_report_rows` rows.
- Admin report listing through
  `GET /_matrix/client/v3/admin/safety/reports`.
- Admin review actions through
  `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}` and, for an operator,
  `POST /_merovingian/admin/review/{targetType}/{targetId}`. Both call `apply_admin_review`
  (`homeserver/OperatorAdmin.cpp`), so the stored policy rule, the audit row and the admin action row are the same;
  only the rendering of a refusal differs (a Matrix error object on the client route, a plain-text line on the
  operator route, ADR-0504). Target types are `media`, `room`, `federation` and `federation_server`; the identifier is
  percent-decoded once (#454).
- Operator account actions through `POST /_merovingian/admin/accounts/{userId}` (`lock`, `unlock`, `suspend`,
  `unsuspend`, and `deactivate` with `"confirm": true`, ADR-0506), with the summary at `GET` on the same path. Lock and
  suspend use `set_local_user_moderation`, the write the spec's `/admin/lock` and `/admin/suspend` endpoints use.
- Admin policy-rule management through
  `GET /_matrix/client/v3/admin/safety/policy_rules`,
  `PUT /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}`, and
  `DELETE /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}`.
  A rule's action is one of `allow`, `deny`, `quarantine`, `lock_account` or
  `suspend_account`; any other value is rejected. The scope must be one something reads: `registration`, `federation`,
  `media` or `room`; any other scope is `400 M_INVALID_PARAM` and nothing is stored (ADR-0500). The engine's `PolicyAction`
  also has `accept_report`, used only for event-report decisions.
- Remote policy-server transport through
  `security.trust_safety.policy_server_url` and the fail-closed
  `PolicyServerHook` path (F-42, ADR-0361). The operator chose the host, so
  `resolve_policy_server_hook` resolves it itself, with no SSRF deny-list (a
  policy server on a private network works), inside the lock-release scope and
  within what is left of `policy_server_timeout`, and pins the request to the
  addresses it found. Certificate validation is unchanged. Each call takes a
  place in `policy_server_budget` first: at most a quarter of
  `server.http.request_threads` (at least 2) in flight across all surfaces, and
  half of that for any one surface, so a flood of federation requests leaves
  registration and room creation a place. A call refused for lack of a place
  is "no usable decision", exactly like an unreachable server: refused when
  `policy_server_allow_without_result=false` (the default), allowed when `true`.
  A transport error is logged at warning level with its error name. The hook
  runs in main only; federation requests are judged by the proxy. For the
  federation surface a real decision is kept per origin for 30 seconds, one
  request at a time asks and the origin's other requests wait for it, and an
  origin decided about within ten minutes keeps that decision when the budget
  has no place left (ADR-0635); other failures, and every other surface, are
  unchanged.
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
  shown. Ignored users' events also do not raise that user's unread or highlight counts
  (`unread_notifications`, sliding-sync room counts, Push Gateway `counts.unread`; 0.12.76, F-64). See "Deliberately not included" below for what it does not protect
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
