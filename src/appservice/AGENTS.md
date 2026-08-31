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
| `appservice_client.cpp` | Outbound `PUT /transactions/{txnId}`, `GET /users/{userId}`, `GET /rooms/{roomAlias}`, and the five `GET /thirdparty/*` third-party lookup calls |

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
- **Aggregation degrades, never fails**: an appservice that times out,
  refuses the connection, or returns a non-200/malformed body contributes
  nothing and is skipped — it does not turn the whole client request into an
  error. Only when *no* appservice contributed anything does the route
  answer 404 (or `{}` for `/protocols`).
- **`instance_id` is homeserver-minted**, never trusted from the appservice
  reply (spec: "This field is added to the response ... by the homeserver").
  It is `<registration id>:<instance index>`, unique across the homeserver
  because registration `id`s are enforced unique at load time.
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
  keys are **parse failures**, never silently coerced. Booleans are
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
- Both outbound calls use `homeserver::ScopedGuardRelease`, so `runtime.mutex`
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
- **An appservice's own `sender_localpart` user is not checked against another
  appservice's exclusive namespace.** That needs the server name to build a
  full user id, and neither `validate_registrations()` nor the registration
  loader currently has one.
