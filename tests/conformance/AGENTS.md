# Conformance Tests

This directory contains **strict Matrix v1.18 specification conformance tests** for Merovingian.

## Purpose

Every test in this directory directly encodes a **MUST** or **SHOULD** from the Matrix specification. They exist to prove that Merovingian's behaviour matches the spec exactly — not that the code compiles or that internal data structures work.

## Rules — Non-Negotiable

1. **Never weaken an assertion to make CI pass.** If a test fails, fix the implementation.
2. **Never remove or comment out a `REQUIRE`.** Removing an assertion is removing spec coverage.
3. **Never change an expected value without citing the spec change.** If a value changes, quote the spec section and version that changed it.
4. **The spec is the authority.** Not Synapse, not other implementations, not intuition.
5. **Cite the spec section above every `SCENARIO`.** Use the URL format shown below.

## File Naming Convention

| File | Spec section(s) covered |
|------|------------------------|
| `test_canonicaljson_parser.cpp` | [Appendices § Canonical JSON](https://spec.matrix.org/v1.18/appendices/#canonical-json) |
| `test_canonicaljson_serializer.cpp` | [Appendices § Canonical JSON](https://spec.matrix.org/v1.18/appendices/#canonical-json) |
| `test_client_server_conformance.cpp` | [Client-Server API](https://spec.matrix.org/v1.18/client-server-api/) |
| `test_event_auth_rules.cpp` | [Auth Rules](https://spec.matrix.org/v1.18/server-server-api/#authorization-rules) |
| `test_event_authorization.cpp` | [Auth Rules — Authorization](https://spec.matrix.org/v1.18/server-server-api/#authorization-rules) |
| `test_event_relationships_conformance.cpp` | [CS API § Event Relationships](https://spec.matrix.org/v1.18/client-server-api/#forming-relationships-between-events) |
| `test_events.cpp` | [SS API § Event Signing](https://spec.matrix.org/v1.18/server-server-api/#signing-events) · [§ Content Hash](https://spec.matrix.org/v1.18/server-server-api/#calculating-the-content-hash-for-an-event) |
| `test_federation_conformance.cpp` | [Server-Server API](https://spec.matrix.org/v1.18/server-server-api/) |
| `test_federation_transaction_conformance.cpp` | [SS API § PUT /send/{txnId}](https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv1sendtxnid) |
| `test_identifier_grammar.cpp` | [Appendices § Identifier Grammar](https://spec.matrix.org/v1.18/appendices/#identifier-grammar) |
| `test_key_publication_conformance.cpp` | [SS API § Key publication](https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server) |
| `test_pdu_format_conformance.cpp` | [SS API § PDUs](https://spec.matrix.org/v1.18/server-server-api/#pdus) |
| `test_redaction_conformance.cpp` | [SS API § Redaction](https://spec.matrix.org/v1.18/server-server-api/#redactions) |
| `test_room_version_table_conformance.cpp` | [Room Versions](https://spec.matrix.org/v1.18/rooms/) |
| `test_server_discovery.cpp` | [SS API § Resolving Server Names](https://spec.matrix.org/v1.18/server-server-api/#resolving-server-names) |
| `test_signing_json_conformance.cpp` | [Appendices § Signing JSON](https://spec.matrix.org/v1.18/appendices/#signing-json) |
| `test_state_resolution_conformance.cpp` | [SS API § State Resolution](https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution) |
| `test_sync_filter_conformance.cpp` | [CS API § Filtering](https://spec.matrix.org/v1.18/client-server-api/#filtering) |
| `test_x_matrix_auth_parsing.cpp` | [SS API § X-Matrix Auth](https://spec.matrix.org/v1.18/server-server-api/#request-authentication) |

## How to Write Conformance Tests

Every `SCENARIO` must carry a spec citation in the comment block immediately above it:

```cpp
// Spec: Matrix Server-Server API v1.18
// Endpoint / Section: <name>
// URL: https://spec.matrix.org/v1.18/<section>/#<anchor>
//
// Summary of the MUST/SHOULD being tested.
SCENARIO("descriptive test name", "[area][conformance][tag]")
```

- Use `[conformance]` as a tag on every scenario.
- Add additional tags matching the spec area: `[canonicaljson]`, `[federation]`, `[client-server]`, `[auth]`, `[signing]`, `[identifiers]`, etc.
- Each `REQUIRE` line should have a one-line comment quoting "Spec MUST:" or "Spec SHOULD:" with the key constraint.

## When a Test Fails

A failing conformance test means **the implementation is wrong**, not the test. The correct response is always:

```
Fix the implementation → verify the fix → re-run → confirm the test passes
```

Do **not** amend the test to accept the wrong behaviour.

## Spec Reference

- Base spec: https://spec.matrix.org/v1.18/
- Client-Server API: https://spec.matrix.org/v1.18/client-server-api/
- Server-Server API: https://spec.matrix.org/v1.18/server-server-api/
- Room Versions: https://spec.matrix.org/v1.18/rooms/
- Appendices: https://spec.matrix.org/v1.18/appendices/
