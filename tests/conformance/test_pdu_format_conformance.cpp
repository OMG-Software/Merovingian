// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX PDU FORMAT CONFORMANCE TESTS                             |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18 — PDUs                            |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/#pdus            |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  Required top-level PDU fields (room v3+):                              |
// |    type, room_id, sender, origin_server_ts, content,                    |
// |    hashes (with sha256), prev_events, auth_events, depth, signatures    |
// +-------------------------------------------------------------------------+

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

// A fully valid room-v3+ PDU. All required fields are present.
auto const valid_pdu = std::string{
    "{\"type\":\"m.room.message\","
    "\"room_id\":\"!room:example.org\","
    "\"sender\":\"@alice:example.org\","
    "\"content\":{\"msgtype\":\"m.text\",\"body\":\"hello\"},"
    "\"depth\":5,"
    "\"hashes\":{\"sha256\":\"abc123\"},"
    "\"origin_server_ts\":1000000,"
    "\"prev_events\":[\"$prev:example.org\"],"
    "\"auth_events\":[\"$create:example.org\"],"
    "\"signatures\":{\"example.org\":{\"ed25519:1\":\"sig\"}}}"};

} // namespace

// Spec: Matrix Server-Server API v1.18 — PDUs
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// parse_federation_pdu must correctly extract the core fields from a valid
// room-v3+ PDU JSON string.
SCENARIO("parse_federation_pdu extracts required fields from a valid room v3+ PDU",
         "[pdu][format][conformance]")
{
    GIVEN("a valid room-v3+ PDU JSON string")
    {
        WHEN("parse_federation_pdu is called")
        {
            auto const pdu = merovingian::federation::parse_federation_pdu(valid_pdu);

            THEN("the PDU type is extracted correctly")
            {
                // Spec MUST: type is a required string field.
                REQUIRE(pdu.event_type == "m.room.message");
            }

            THEN("the PDU room_id is extracted correctly")
            {
                // Spec MUST: room_id is a required string field.
                REQUIRE(pdu.room_id == "!room:example.org");
            }

            THEN("the PDU sender is extracted correctly")
            {
                // Spec MUST: sender is a required string field.
                REQUIRE(pdu.sender == "@alice:example.org");
            }

            THEN("the PDU JSON is preserved")
            {
                // Spec behaviour: the raw JSON must be preserved for signature verification.
                REQUIRE(!pdu.json.empty());
            }

            THEN("the PDU has at least one signature")
            {
                // Spec MUST: PDUs must carry a signatures object with at least
                // one entry from the sending server.
                REQUIRE(!pdu.signatures.empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Signing Events
// URL: https://spec.matrix.org/v1.18/server-server-api/#signing-events
//
// The spec requires that a PDU carries a valid signature from the sender's server
// (domain_of(sender)). For room v1/v2 rooms, the event-ID server must also have
// signed. The transaction origin (the server that delivered the PDU) need not be
// the sender's server — the spec explicitly permits transit-server delivery.
//
// The spec-required validation is therefore: "does the PDU have a valid signature
// from domain_of(sender)?" — NOT "does the transport origin equal domain_of(sender)?".
//
// Merovingian additionally enforces that the transport origin matches domain_of(sender)
// as a hardening policy; that behaviour is NOT a spec MUST and is tested in the
// unit tests (test_federation_inbound_request.cpp: "Federation PDU authorization
// rejects sender origin and event signature mismatches").
SCENARIO("authorize_federation_pdu validates sender-server signatures (spec requirement)",
         "[pdu][format][conformance]")
{
    GIVEN("a PDU from @alice:example.org signed by example.org")
    {
        auto const pdu = merovingian::federation::parse_federation_pdu(valid_pdu);

        WHEN("the expected origin is 'example.org' — the sender's server domain")
        {
            auto const decision =
                merovingian::federation::authorize_federation_pdu(pdu, "example.org");

            THEN("the PDU is accepted — sender-server signature is present and valid")
            {
                // Spec MUST: a PDU that carries a valid signature from domain_of(sender)
                // MUST be accepted. '@alice:example.org' → sender server is 'example.org'.
                REQUIRE(decision.accepted);
            }
        }

        WHEN("the PDU carries no signature at all (signatures list cleared)")
        {
            auto unsigned_pdu = pdu;
            unsigned_pdu.signatures.clear();
            auto const decision =
                merovingian::federation::authorize_federation_pdu(unsigned_pdu, "example.org");

            THEN("the PDU is rejected — missing sender-server signature")
            {
                // Spec MUST: a PDU without a valid signature from domain_of(sender)
                // MUST be rejected. Unsigned events cannot be attributed to any server.
                REQUIRE_FALSE(decision.accepted);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — PDUs
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// parse_inbound_pdu_envelope extracts the room-version-agnostic fields from a
// PDU JSON string. A valid envelope must carry room_id, sender, event_type,
// origin_server_ts, depth, prev_events, and auth_events.
SCENARIO("parse_inbound_pdu_envelope extracts the full PDU envelope",
         "[pdu][format][conformance]")
{
    GIVEN("a valid room-v3+ PDU JSON string")
    {
        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(valid_pdu);

            THEN("an envelope is returned (not nullopt)")
            {
                // Spec MUST: a structurally valid PDU must produce an envelope.
                REQUIRE(envelope.has_value());
            }

            THEN("the sender field is populated")
            {
                REQUIRE(envelope->sender == "@alice:example.org");
                // Spec MUST: sender is a required string field.
            }

            THEN("the event_type field is populated")
            {
                REQUIRE(envelope->event_type == "m.room.message");
            }

            THEN("the room_id field is populated")
            {
                REQUIRE(envelope->room_id == "!room:example.org");
            }

            THEN("origin_server_ts is populated and non-zero")
            {
                // Spec MUST: origin_server_ts is a required integer (ms since epoch).
                REQUIRE(envelope->origin_server_ts > 0);
            }

            THEN("depth is populated")
            {
                // Spec MUST: depth is a required non-negative integer.
                REQUIRE(envelope->depth >= 0U);
            }

            THEN("prev_events is populated")
            {
                // Spec MUST: prev_events is a required array (may be empty for create events).
                REQUIRE(!envelope->prev_event_ids.empty());
                REQUIRE(envelope->prev_event_ids.front() == "$prev:example.org");
            }

            THEN("auth_events is populated")
            {
                // Spec MUST: auth_events is a required array.
                REQUIRE(!envelope->auth_event_ids.empty());
                REQUIRE(envelope->auth_event_ids.front() == "$create:example.org");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — PDUs
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// parse_inbound_pdu_envelope must return nullopt for structurally invalid input
// (missing required fields, wrong types, invalid JSON).
SCENARIO("parse_inbound_pdu_envelope rejects structurally invalid PDUs",
         "[pdu][format][conformance]")
{
    GIVEN("a PDU JSON missing the required 'type' field")
    {
        auto const no_type = std::string{
            "{\"room_id\":\"!room:example.org\","
            "\"sender\":\"@alice:example.org\","
            "\"content\":{},"
            "\"depth\":1,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":1000,"
            "\"prev_events\":[],\"auth_events\":[],"
            "\"signatures\":{}}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(no_type);

            THEN("nullopt is returned")
            {
                // Spec MUST: a PDU without 'type' is invalid and must be rejected.
                REQUIRE(!envelope.has_value());
            }
        }
    }

    GIVEN("a PDU JSON missing the required 'sender' field")
    {
        auto const no_sender = std::string{
            "{\"type\":\"m.room.message\","
            "\"room_id\":\"!room:example.org\","
            "\"content\":{},"
            "\"depth\":1,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":1000,"
            "\"prev_events\":[],\"auth_events\":[],"
            "\"signatures\":{}}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(no_sender);

            THEN("nullopt is returned")
            {
                // Spec MUST: a PDU without 'sender' is invalid and must be rejected.
                REQUIRE(!envelope.has_value());
            }
        }
    }

    GIVEN("a PDU JSON missing the required 'room_id' field")
    {
        auto const no_room_id = std::string{
            "{\"type\":\"m.room.message\","
            "\"sender\":\"@alice:example.org\","
            "\"content\":{},"
            "\"depth\":1,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":1000,"
            "\"prev_events\":[],\"auth_events\":[],"
            "\"signatures\":{}}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(no_room_id);

            THEN("nullopt is returned")
            {
                // Spec MUST: a PDU without 'room_id' is invalid and must be rejected.
                REQUIRE(!envelope.has_value());
            }
        }
    }

    GIVEN("an empty JSON object as PDU")
    {
        WHEN("parse_inbound_pdu_envelope is called on '{}'")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope("{}");

            THEN("nullopt is returned")
            {
                // Spec MUST: an empty object is not a valid PDU.
                REQUIRE(!envelope.has_value());
            }
        }
    }

    GIVEN("syntactically invalid JSON as PDU")
    {
        WHEN("parse_inbound_pdu_envelope is called on malformed JSON")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope("{not valid json}");

            THEN("nullopt is returned")
            {
                // Spec behaviour: invalid JSON is unconditionally rejected.
                REQUIRE(!envelope.has_value());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — PDUs
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// "depth" must be an integer >= 1 (the create event has depth 0 by convention;
// all subsequent events have depth >= 1). The spec says depth is a "positive
// integer" for non-create events, and 0 for the create event.
SCENARIO("PDU envelope extracts depth correctly from the JSON",
         "[pdu][format][conformance]")
{
    GIVEN("a valid PDU with depth 7")
    {
        auto const pdu_with_depth = std::string{
            "{\"type\":\"m.room.message\","
            "\"room_id\":\"!room:example.org\","
            "\"sender\":\"@alice:example.org\","
            "\"content\":{\"msgtype\":\"m.text\",\"body\":\"hi\"},"
            "\"depth\":7,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":2000,"
            "\"prev_events\":[\"$prev:example.org\"],"
            "\"auth_events\":[\"$create:example.org\"],"
            "\"signatures\":{}}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_with_depth);
            REQUIRE(envelope.has_value());

            THEN("depth is 7")
            {
                // Spec MUST: depth is serialised as an integer and parsed as-is.
                REQUIRE(envelope->depth == 7U);
            }
        }
    }

    GIVEN("a valid v10 m.room.create PDU with room_id and depth 0")
    {
        // v10 and earlier create events DO include room_id.
        auto const create_pdu = std::string{
            "{\"type\":\"m.room.create\","
            "\"state_key\":\"\","
            "\"room_id\":\"!room:example.org\","
            "\"sender\":\"@alice:example.org\","
            "\"content\":{\"creator\":\"@alice:example.org\",\"room_version\":\"10\"},"
            "\"depth\":0,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":1000,"
            "\"prev_events\":[],"
            "\"auth_events\":[],"
            "\"signatures\":{}}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(create_pdu);
            REQUIRE(envelope.has_value());

            THEN("depth is 0")
            {
                // Spec: the create event has depth 0 by definition.
                REQUIRE(envelope->depth == 0U);
            }

            THEN("state_key is populated")
            {
                // Spec MUST: state events carry a state_key field.
                REQUIRE(envelope->state_key.has_value());
                REQUIRE(envelope->state_key.value().empty()); // state_key is "" for create
            }
        }
    }
}

// Spec: Matrix Room Version 12 (MSC4291)
// URL:  https://spec.matrix.org/v1.18/rooms/v12/
//
// "The m.room.create event MUST NOT include a room_id field. The room ID is
// derived from the create event's reference hash: the unpadded base64url of
// the SHA-256 reference hash, prefixed with '!'."
SCENARIO("Room v12: m.room.create PDU without room_id is accepted and room_id is derived",
         "[pdu][format][conformance][room-v12]")
{
    GIVEN("a v12 m.room.create PDU with no room_id field")
    {
        // Spec MUST: v12 create events MUST NOT have a room_id field.
        auto const v12_create = std::string{
            "{\"auth_events\":[],"
            "\"content\":{\"creator\":\"@alice:example.org\",\"room_version\":\"12\"},"
            "\"depth\":0,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":1000,"
            "\"prev_events\":[],"
            "\"sender\":\"@alice:example.org\","
            "\"signatures\":{},"
            "\"state_key\":\"\","
            "\"type\":\"m.room.create\"}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(v12_create);

            THEN("the envelope is successfully parsed")
            {
                // Spec MUST: a valid v12 create event without room_id MUST be accepted.
                REQUIRE(envelope.has_value());
            }

            THEN("the room_id is derived from the event's reference hash")
            {
                // Spec MUST: room_id = '!' + same base64url hash as the event_id.
                // The room_id starts with '!' and has no ':' domain separator.
                REQUIRE(envelope.has_value());
                REQUIRE_FALSE(envelope->room_id.empty());
                REQUIRE(envelope->room_id.front() == '!');
                REQUIRE(envelope->room_id.find(':') == std::string::npos);
                // room_id and event_id share the same base64url body, different sigil.
                REQUIRE(envelope->room_id.substr(1U) == envelope->event_id.substr(1U));
            }

            THEN("event_type is m.room.create")
            {
                REQUIRE(envelope.has_value());
                // Spec MUST: event type is preserved exactly.
                REQUIRE(envelope->event_type == "m.room.create");
            }
        }
    }
}

// Spec: Matrix Room Version 12 (MSC4291)
// URL:  https://spec.matrix.org/v1.18/rooms/v12/
//
// "The m.room.create event MUST NOT appear in the auth_events of any other
// event. In room version 12, the create event ID is derived deterministically
// from the room ID (same hash, '!' → '$'), making violations detectable at
// parse time without a store lookup."
SCENARIO("Room v12: PDU with m.room.create in auth_events is rejected",
         "[pdu][format][conformance][room-v12]")
{
    // A 43-char base64url hash, matching what a real v12 room looks like.
    // room_id = "!AAAA..." means create_event_id = "$AAAA...".
    static constexpr auto k_v12_hash = std::string_view{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};

    GIVEN("a v12 non-create event that lists the create event in auth_events")
    {
        auto const v12_room_id = "!" + std::string{k_v12_hash};
        auto const v12_create_id = "$" + std::string{k_v12_hash};
        auto const bad_pdu = std::string{
            "{\"auth_events\":[\"" + v12_create_id + "\"],"
            "\"content\":{\"body\":\"hello\",\"msgtype\":\"m.text\"},"
            "\"depth\":5,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":2000,"
            "\"prev_events\":[],"
            "\"room_id\":\"" + v12_room_id + "\","
            "\"sender\":\"@alice:example.org\","
            "\"signatures\":{},"
            "\"type\":\"m.room.message\"}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(bad_pdu);

            THEN("nullopt is returned")
            {
                // Spec MUST: v12 create event MUST NOT appear in any other event's
                // auth_events. Such a PDU is malformed and must be rejected.
                REQUIRE_FALSE(envelope.has_value());
            }
        }
    }

    GIVEN("a v12 non-create event whose auth_events does NOT contain the create event")
    {
        auto const v12_room_id = "!" + std::string{k_v12_hash};
        auto const other_event_id = "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBbb";
        auto const good_pdu = std::string{
            "{\"auth_events\":[\"" + std::string{other_event_id} + "\"],"
            "\"content\":{\"body\":\"hello\",\"msgtype\":\"m.text\"},"
            "\"depth\":5,"
            "\"hashes\":{\"sha256\":\"x\"},"
            "\"origin_server_ts\":2000,"
            "\"prev_events\":[],"
            "\"room_id\":\"" + v12_room_id + "\","
            "\"sender\":\"@alice:example.org\","
            "\"signatures\":{},"
            "\"type\":\"m.room.message\"}"};

        WHEN("parse_inbound_pdu_envelope is called")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(good_pdu);

            THEN("the envelope is successfully parsed")
            {
                // Spec: a well-formed v12 non-create event without create event in
                // auth_events MUST be accepted.
                REQUIRE(envelope.has_value());
            }
        }
    }
}
