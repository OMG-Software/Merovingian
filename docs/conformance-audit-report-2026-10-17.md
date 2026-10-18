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
| R04 | P2 | Resident restricted-room joins fail at template creation and resident signing | Open — wave 2 |
| R05 | P2 | Relayed PDU signature checks use only the first key ID listed | Open — wave 2 |
| R06 | P2 | Direct membership endpoints reject a hash mismatch instead of redacting | Open — wave 2 |
| R07 | P2 | Appservices miss invites to their own virtual users | Open — wave 3 |
| R08 | P2 | `receive_ephemeral` is parsed but no ephemeral data is sent | Open — wave 3 |
| R09 | P2 | Identity-server `requestToken` calls drop `send_attempt` | Open — wave 3 |
| R10 | P2 | Room-scoped account data GET/PUT are absent | Open — wave 4 |
| R11 | P2 | Global account data accepts non-object and malformed JSON | Open — wave 4 |
| R12 | P2 | Registration rejects an omitted username instead of generating one | Open — wave 4 |
| R13 | P2 | Local typing never expires; non-boolean `typing` is treated as true | Open — wave 4 |
| R15 | P2 | Unread counts ignore push-rule notify/highlight actions | Open — wave 5 |
| R17 | P2 | Authenticated `{fileName}` media downloads fail for existing media | Open — wave 4 |
| R19 | P2 | Push-rule mutation APIs are absent; delivery uses read-only defaults | Open — wave 5 |
| R14 | P3 | Failed push notifications are never retried (spec SHOULD) | Open — wave 5 |
| R16 | P3 | `/search` omits visible history from rooms the user has left | Open — wave 4 |
| R18 | P3 | Federation profile queries reject `field=m.tz` | Open — wave 2 |

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

### Found while fixing R01 (open)

- `create_room` never queues its own events (create, member, power levels, join rules…) for
  appservices; only `send_event`, membership transitions and federation PDUs do. Wave 3.
- The outbox of an appservice that never returns grows without bound (ADR-0163).

## Additional endpoint and feature gaps

All confirmed absent. Applicability varies; an optional feature that is absent is recorded as
unsupported, not as a violation.

| Surface | Status |
|---------|--------|
| `POST /_matrix/client/v1/appservice/{appserviceId}/ping` | Open — wave 3 |
| `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` | Open — wave 3 |
| `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event` | Open — wave 6 (to decide) |
| `POST /_matrix/media/v1/create` and `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` | Open — wave 6 (to decide) |
| `GET /_matrix/client/v1/media/preview_url` | Open — wave 6 (optional; SSRF boundary) |
| `GET /_matrix/client/v3/presence/{userId}/status` | Open — wave 6 (to decide) |
| `POST /_matrix/client/v1/login/get_token` | Optional; `m.get_login_token` stays disabled |
| Deprecated `/events`, `/events/{eventId}`, `/initialSync` | Compatibility omissions |
| Room versions 1 and 2 | Deliberately unsupported; not advertised |

## Concerns not promoted to findings

1. Unread counts count pre-join messages in a `joined`-visibility room (no content disclosed).
   Reconsider with R15.
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
| 2 | — | R04, R05, R06, R18 (federation) |
| 3 | — | R07, R08, R09, appservice ping and network directory, `create_room` appservice delivery |
| 4 | — | R10, R11, R12, R13, R16, R17 (client API) |
| 5 | — | R19, then R15 and R14 (push rules, counts, retry) |
| 6 | — | Optional endpoint gaps, after a decision on each |
