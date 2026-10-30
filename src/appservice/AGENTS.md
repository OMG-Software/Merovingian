# src/appservice/ — Application Service API support

Implements the Matrix v1.19 Application Service API
(`docs/matrix-v1.19-spec/application-service-api.md`): registration-file
parsing, namespace matching and exclusivity, the in-memory registry, identity
assertion (`?user_id=`), and the outbound `/_matrix/app/v1/*` client.

| File | Responsibility |
|---|---|
| `registration.cpp` | Record types, JSON parsing, namespace matching and exclusivity, registry lookup, cross-registration validation |
| `registration_yaml.cpp` | The bounded YAML-subset parser — the format real registration files actually use |
| `masquerade_token.cpp` | `?user_id=` identity assertion, scoped to the asserting appservice's namespaces |
| `appservice_client.cpp` | Outbound `PUT /transactions/{txnId}` (with the optional `ephemeral` array), `POST /ping`, `GET /users/{userId}`, `GET /rooms/{roomAlias}`, and the five `GET /thirdparty/*` third-party lookup calls |

## Third-party lookups

The client-server `GET /_matrix/client/v3/thirdparty/{protocols,protocol/{p},
location,location/{p},user,user/{p}}` routes (routed in
`homeserver/client_server.cpp`) are backed by `AppserviceClient::
query_thirdparty_protocol`/`query_thirdparty_location_by_alias`/
`query_thirdparty_location_by_protocol`/`query_thirdparty_user_by_userid`/
`query_thirdparty_user_by_protocol` in `appservice_client.cpp`.

- **Ownership**: a protocol name is "owned" by whichever registration lists
  it in `protocols:`. `protocol/{p}` and `location|user/{p}` route only to
  the owning registration(s); an unrecognised protocol name is `404
  M_NOT_FOUND` without any outbound call. The bare `location`/`user` routes
  (alias/userid lookup) have no such ownership signal, so they fan out to
  *every* registered appservice and aggregate.
- **Every such client request holds an ADR-0079 slot** (`admit_client_proxy`) before the first outbound
  call, and each appservice keeps its own timeout (ADR-0181, which rejected one shared deadline because it
  would drop later appservices' answers from the aggregate).
- **Aggregation degrades, never fails**: an appservice that times out,
  refuses the connection, or returns a non-200/malformed body contributes
  nothing and is skipped — it does not turn the whole client request into an
  error. Only when *no* appservice contributed anything does the route
  answer 404 (or `{}` for `/protocols`).
- **`instance_id` is homeserver-minted**, never trusted from the appservice
  reply (spec: "This field is added to the response ... by the homeserver").
  It is `<registration id>:<protocol>:<instance index>` (see "Instance IDs"),
  unique across the homeserver because registration `id`s are enforced unique
  at load time and the protocol is part of the ID.
- **Untrusted response parsing**: `parse_thirdparty_protocol_response`/
  `parse_thirdparty_location_response`/`parse_thirdparty_user_response` are
  pure, network-free, and exported specifically so the bounded/type-checked
  extraction (dropped malformed entries, non-string `fields` members
  dropped, capped array/object sizes — see the constants at the top of
  `appservice_client.cpp`) is unit-testable without a mock server. A bridge
  is not a trusted peer: never widen these bounds without updating the
  corresponding unit test.

## Registration files

- **YAML is the real format.** The spec's own example and every shipped bridge
  use block-style `registration.yaml`. JSON is a subset of YAML 1.2, so JSON
  files parse too, but treating JSON as sufficient means loading no real
  bridge — that was a live bug. `load_registration_file()` tries YAML first
  and falls back to JSON.
- `registration_yaml.cpp` is a **strict, bounded YAML subset**, not a general
  YAML parser: 2-space-indented block maps and lists, plain/single-/double-quoted
  scalars, `#` comments, `null`/`~`.
- Anchors, aliases, tags, block scalars, tabs, document markers and unknown
  keys are **parse failures**, never silently coerced. The one exception (ADR-0273): a
  reverse-DNS namespaced key (lower case, at least one dot, e.g. `org.matrix.msc3202`) and
  MSC2409's `push_ephemeral` are skipped and logged at warning as `registration.key_ignored`;
  their values are never read. A typo of a real key is still a finding. Booleans are
  `true`/`false` only — the YAML 1.1 spellings (`yes/no/on/off`) are rejected
  because real YAML parsers disagree about them.
- **Flow collections**: only the empty sequence `[]` is accepted, because the
  spec's example writes an absent namespace as `rooms: []`. A non-empty flow
  sequence is rejected rather than parsed partially or dropped silently.
- Bounds, fail closed: 256 KiB file, 4 KiB line, 64 entries per namespace list,
  32 protocols. A registration file is operator-authored configuration, so
  anything larger than what real bridges ship is a finding, not a
  resource-exhaustion opportunity.

## Namespaces

- Patterns are **POSIX ERE** per the spec (`std::regex::extended`).
- Match with `std::regex_match`, **never `std::regex_search`**. A namespace
  regex is a claim over a whole identifier, not a substring: under an
  unanchored search the spec's own example `@_irc_.*` also claims
  `@evil@_irc_bob:example.org`, letting one appservice's *exclusive* namespace
  swallow unrelated local users and block their registration.
- A malformed operator-supplied regex must fail closed to "no match" — never
  crash the request path, and never degrade to "matches everything".
- **Compile once.** `Namespace`'s constructor compiles the pattern and keeps it
  in `compiled` (shared between copies; null for a malformed pattern).
  `any_namespace_matches` and `any_exclusive_namespace_matches` match against
  it. Namespace matching runs per member per event under `runtime.mutex`, so
  never compile a pattern on a request path. `namespace_matches(pattern, value)`
  compiles per call and is for one-off checks only.

## Interest (R07)

`registration_interested_in_room_event(registration, server_name, EventInterestFacts)` decides whether an
event is queued for an appservice. The spec's definition is: the `rooms` namespace matches the room ID, the
`aliases` namespace matches **any** alias of the room, and the `users` namespace (plus `sender_localpart`)
matches the sender, **the target of the event**, or a joined member. The target of an `m.room.member` event is
its `state_key`, so an invite to a virtual user who has not joined is delivered; pass it as
`member_event_target` (callers get it from `ComposedEvent::state_key`). Only local users count
(`appservice_owns_user` checks the server name), so a remote user matching a namespace regex never makes an
appservice interested by itself. Never reduce the facts back to a single alias or drop the target.

## Ping

`AppserviceClient::ping` sends `POST /_matrix/app/v1/ping` (`{"transaction_id": ...}` or `{}`) with the
hs_token and classifies the outcome as an `AppservicePingFailure`: `url_not_set` (400), `connection_timeout`
(`OutboundError::timeout`, 504), `bad_status` (the appservice answered, including a refused redirect; 502 with
its status and at most `max_ping_body_bytes` of its body) or `connection_failed` (anything else, 502). The
caller releases `runtime.mutex` (`RuntimeLockRelease`) and holds an ADR-0079 slot for the call.

## Instance IDs

`instance_id` is `<registration id>:<protocol>:<index>`, the first two percent-encoded, minted by
`thirdparty_protocol_json`. The protocol is part of it because a registration with two protocols would
otherwise mint `id:0` twice, and so that a `third_party_instance_id` in `POST /publicRooms` resolves to the
directory network (appservice, protocol) it names without asking the appservice (ADR-0192).

## Security rules

- `as_token` and `hs_token` live in `core::SecretBuffer`. Never log them. The
  `hs_token` must stay reversible because it is transmitted to the appservice;
  it cannot be stored as a hash.
- Compare tokens with `crypto::constant_time_equal`, never `==`.
- Registration `id` and `as_token` MUST be unique per appservice — the spec
  requires the homeserver to enforce it. `validate_registrations()` is that
  enforcement and runs at boot.
- Identity assertion (`?user_id=`) must be scoped to the asserting
  appservice's own namespaces. An appservice asserting a user outside its
  namespaces is a privilege escalation, not a lookup miss.
- **Other services' exclusive namespaces are honoured** on `/register`
  (`400 M_EXCLUSIVE`, the status the `/register` response table lists),
  `/login` and assertion (`403 M_EXCLUSIVE`) via
  `AppserviceRegistry::user_namespace_exclusively_owned_by_other(user, own_id)`.
  `appservice_owns_user` alone is NOT enough for these: it answers "is this in
  my namespace", and a non-exclusive `@.*` namespace overlaps another
  service's exclusive one (AUTH-7).
- **Assertion acts only as a registered, active user** (`403 M_FORBIDDEN`
  otherwise, AUTH-12). The service creates virtual users with `/register`;
  `/register` and `/login` themselves are exempt from this check because they
  act as the always-present `sender_localpart` user.
- **Assertion never reaches Account Management** (AUTH-8):
  `is_account_management_endpoint` in `masquerade_token.cpp` classifies every
  `/account/*` path except `GET /account/whoami` (fail closed on unknown
  paths under `/account/`). A new `/account/...` endpoint is covered
  automatically; do not add exceptions.

## User and room-alias query hooks

When an identifier inside an appservice's namespace is unknown locally, the
homeserver asks that appservice before answering 404 — a bridge materialises
users and rooms on demand, so a flat 404 makes the namespace pointless.

- Wired at `GET /_matrix/client/v3/directory/room/{roomAlias}` and
  `GET /_matrix/client/v3/profile/{userId}` in `homeserver/client_server.cpp`,
  backed by `AppserviceClient::query_room_alias` / `query_user`.
- **Only the owning appservice is queried.** The spec limits queries to an
  appservice's own namespace, and fanning out would leak which aliases and
  users clients are looking up to bridges with no claim on them.
- **A failing appservice is a miss, not an error.** Unreachable or declining
  contributes nothing; the next candidate is tried and the request ultimately
  404s. A bridge being down must never turn a 404 into a 502.
- Both outbound calls use `homeserver::RuntimeLockRelease`, so `runtime.mutex`
  is released for the round trip and restored even if the call throws.
- Covered by `tests/integration/test_appservice_query_hooks_flow.cpp`, which
  asserts on the bytes actually sent — the outbound half was dead code for its
  whole life and never once failed to compile.

## Cross-registration validation

`validate_registrations()` runs at boot and fails the whole set closed rather
than resolving ambiguity by consultation order. It reports duplicate `id` and
duplicate `as_token` (constant-time compared), and namespace patterns claimed
by two registrations where at least one claims them exclusively.

## Known gaps

- **Namespace-overlap detection compares pattern strings.** Two *different*
  regexes that happen to match overlapping identifiers are not reported.
  Deciding regex intersection in general is not something a boot-time check can
  do, and a false conflict refusing to start a correct deployment would be
  worse than the gap. This catches the realistic operator error: two bridges
  shipping the same pattern.
Closed in 0.12.2: an appservice's `sender_localpart` user IS now checked against
every other registration's exclusive users namespace. `validate_registrations()`
and `load_registrations()` take the homeserver's `server_name` (defaulted empty,
which skips only this check) so the sender user id can be built. A registration's
own sender legitimately sits inside its own exclusive namespace, so the check
never self-compares — flagging that would refuse to start every correct bridge.
