# Merovingian Conformance Audit — 17 October 2026

**Scope:** a read-only, static audit of homeserver responsibilities against Matrix v1.19
(Client-Server, Server-Server, Application Service, Identity Service and Push Gateway APIs,
room versions). It is a broad source-and-test review, not endpoint-by-endpoint certification.
**Baseline:** `b200c912` (0.12.26).
**Method (auditor):** source and tests read at the pinned commit; none of the reproduction
recipes was executed; severity is an engineering priority, not CVSS.
**Method (triage):** every finding was re-located in the 0.12.27 tree (`2da8f96b`) and its
cited control flow re-read before any fix. Spec claims were checked against
`docs/matrix-v1.19-spec/`. All 19 findings and every listed endpoint gap were confirmed.

Priorities: **P1** loses delivery work while reporting success; **P2** protocol,
interoperability or validation defect; **P3** lower priority or recommendation level.

## Findings

| ID | Priority | Finding | Status |
|----|----------|---------|--------|
| R01 | P1 | Application-service outages permanently skip newer events | Fixed 0.12.28 (ADR-0163) |
| R02 | P1 | Local to-device enqueue failure is acknowledged, then deduplicated | Fixed 0.12.28 (ADR-0164) |
| R03 | P1 | A federation PDU with unresolved history is lost after a 200 | Fixed 0.12.28 (ADR-0165) |
| R04 | P2 | Resident restricted-room joins fail at template creation and resident signing | Fixed 0.12.36 (ADR-0184, ADR-0185) |
| R05 | P2 | Relayed PDU signature checks use only the first key ID listed | Fixed 0.12.36 (ADR-0183) |
| R06 | P2 | Direct membership endpoints reject a hash mismatch instead of redacting | Fixed 0.12.36 |
| R07 | P2 | Appservices miss invites to their own virtual users | Fixed 0.12.37 |
| R08 | P2 | `receive_ephemeral` is parsed but no ephemeral data is sent | Fixed 0.12.37 (ADR-0190) |
| R09 | P2 | Identity-server `requestToken` calls drop `send_attempt` | Fixed 0.12.37 |
| R10 | P2 | Room-scoped account data GET/PUT are absent | Fixed 0.12.38 (ADR-0197) |
| R11 | P2 | Global account data accepts non-object and malformed JSON | Fixed 0.12.38 |
| R12 | P2 | Registration rejects an omitted username instead of generating one | Fixed 0.12.38 (ADR-0198) |
| R13 | P2 | Local typing never expires; non-boolean `typing` is treated as true | Fixed 0.12.38 (ADR-0199) |
| R15 | P2 | Unread counts ignore push-rule notify/highlight actions | Fixed 0.12.40 (ADR-0205) |
| R17 | P2 | Authenticated `{fileName}` media downloads fail for existing media | Open — media wave (0.12.40) |
| R19 | P2 | Push-rule mutation APIs are absent; delivery uses read-only defaults | Fixed 0.12.40 (ADR-0204) |
| R20 | P2 | `POST /register` runs User-Interactive Authentication before the username checks | Open — unscheduled |
| R14 | P3 | Failed push notifications are never retried (spec SHOULD) | Fixed 0.12.40 (ADR-0206) |
| R16 | P3 | `/search` omits visible history from rooms the user has left | Fixed 0.12.38 |
| R18 | P3 | Federation profile queries reject `field=m.tz` | Fixed 0.12.36 |

### Triage notes

- **R05:** the first-key dependence applies to *relayed* membership and invite events and to
  the restricted-join authorising server. When the sender's server is the request origin, the
  X-Matrix key is used and there is no key-ID loop.
- **R09:** `send_attempt` is parsed, validated (≥ 1) and stored in the local 3PID session; it
  is only lost on the outbound identity-server call.
- **R17:** the existing `{fileName}` conformance scenarios assert 404 for *missing* media, so
  they pass whether or not the named route works.
- **R10, R19 and several endpoint gaps** have conformance scenarios that assert
  `404 M_UNRECOGNIZED` as the expected result. Each is replaced by normative success assertions
  as the feature lands.

### Found while fixing R02 (fixed in 0.12.28, ADR-0166)

- Outbound `m.direct_to_device` used the client transaction ID as `message_id`. Transaction
  IDs are unique only per user, so the receiver dropped a second local user's message with the
  same ID as a replay, and an ID over 32 codepoints was invalid.
- Inbound `m.direct_to_device` recorded the `message_id` before storing the messages, one
  commit per device, so a failed store left the EDU half stored and its resend was dropped as a
  replay.

### Found while fixing wave 2 (fixed in 0.12.36)

- R05 is fixed to the spec's rule, not "any one key verifies": unknown keys and keys expired
  before `origin_server_ts` are skipped, every other listed signature must verify, and one must
  ("If all signatures from known unexpired keys ... are found to be valid"; ADR-0183).
- The `make_join` template provider read room state without the runtime lock.

### Found while fixing R01 (fixed in 0.12.37)

- `create_room` never queues its own events (create, member, power levels, join rules…) for
  appservices; only `send_event`, membership transitions and federation PDUs do. Fixed 0.12.37.
- The outbox of an appservice that never returns grows without bound (ADR-0163). Fixed 0.12.37:
  capped by `appservice.max_queued_events` (ADR-0191).

### Found while fixing R07 and R08 (fixed in 0.12.37)

- An invite received on `PUT /_matrix/federation/v2/invite` for a room this server is not in (the
  usual way a remote user invites a bridged user) was stored without being queued for appservices,
  and no transaction brings it again.
- The m.presence a profile change sends was not offered to appservices.
- The ping dropped an empty `transaction_id` instead of copying it.

### Found while fixing wave 4 (open)

- **R20:** `POST /register` runs User-Interactive Authentication before the username checks. The spec says
  homeservers "MUST perform the relevant checks and return these codes before performing
  User-Interactive Authentication" (`M_USER_IN_USE`, `M_INVALID_USERNAME`, `M_EXCLUSIVE`), so a
  client without a registration token learns that its username is unusable only after the UIA
  round. Not part of R12, which is about an omitted `username`; tracked as its own finding, not yet
  scheduled.
- "Servers must allow clients to read the above event types as normal" (Client Config): push
  rules are not kept as `m.push_rules` account data, so `GET /user/{userId}/account_data/m.push_rules`
  is 404. Belongs with R19 (wave 5).

## Additional endpoint and feature gaps

All confirmed absent. Applicability varies; an optional feature that is absent is recorded as
unsupported, not as a violation.

| Surface | Status |
|---------|--------|
| `POST /_matrix/client/v1/appservice/{appserviceId}/ping` | Fixed 0.12.37 |
| `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` | Fixed 0.12.37 (ADR-0192) |
| `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event` | Open — wave 6 (to decide) |
| `POST /_matrix/media/v1/create` and `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` | Open — wave 6 (to decide) |
| `GET /_matrix/client/v1/media/preview_url` | Open — wave 6 (optional; SSRF boundary) |
| `GET /_matrix/client/v3/presence/{userId}/status` | Open — wave 6 (to decide) |
| `POST /_matrix/client/v1/login/get_token` | Optional; `m.get_login_token` stays disabled |
| Deprecated `/events`, `/events/{eventId}`, `/initialSync` | Compatibility omissions |
| Room versions 1 and 2 | Deliberately unsupported; not advertised |

## Concerns not promoted to findings

1. Unread counts count pre-join messages in a `joined`-visibility room (no content disclosed).
   Reconsider with R15. Fixed 0.12.40 with R15: counts start at the user's current join, because
   a keyword rule counted over earlier history would disclose content (ADR-0205).
2. Device-key uploads are not checked for the device's self-signature. The spec puts that
   duty on clients; recorded as a hardening question.
3. Password login with `m.id.thirdparty` / `m.id.phone` identifiers is rejected as bad JSON.
   Wave 6 (to decide).
4. Appservice deliveries could overlap on one cursor. Fixed by R01: one drainer thread.

## Verification evidence

The audit cited CI run 38933712064 at `b200c912`, whose OpenBSD job timed out in
`integration-tests`. 0.12.27 fixed an integration test hung in `connect()` on OpenBSD, and its
branch CI run 39053180514 shows OpenBSD at 58 Ok, 0 Fail.

## Remediation plan

| Wave | Version | Findings |
|------|---------|----------|
| 1 | 0.12.28 | R01, R02, R03, to-device message IDs |
| 2 | 0.12.36 | R04, R05, R06, R18 (federation) |
| 3 | 0.12.37 | R07, R08, R09, appservice ping and network directory, `create_room` appservice delivery |
| 4 | 0.12.38 | R10, R11, R12, R13, R16 (client API); R17 moved to the media wave (0.12.40); R20 found |
| 5 | 0.12.40 | R19, then R15 and R14 (push rules, counts, retry) |
| 6 | — | Optional endpoint gaps, after a decision on each |
