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

## Known gap

Overlapping **exclusive** namespaces *between different appservices* are not
detected. Two registrations may both exclusively claim `@_bridge_.*`, and
whichever is consulted first wins. The spec's exclusivity guarantee is
per-namespace, so this should become a boot-time finding alongside the
duplicate `id`/`as_token` checks in `validate_registrations()`.
