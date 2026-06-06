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

// Spec: Matrix Server-Server API v1.18 — PDUs
// URL: https://spec.matrix.org/v1.18/server-server-api/#pdus
//
// authorize_federation_pdu verifies that the PDU was sent by a server whose
// origin matches the claimed sender domain. A PDU whose sender domain does
// not match the expected origin MUST be rejected.
SCENARIO("authorize_federation_pdu rejects PDU with mismatched origin",
         "[pdu][format][conformance]")
{
    GIVEN("a valid PDU from @alice:example.org")
    {
        auto const pdu = merovingian::federation::parse_federation_pdu(valid_pdu);

        WHEN("the expected origin is 'example.org' (matches sender domain)")
        {
            auto const decision =
                merovingian::federation::authorize_federation_pdu(pdu, "example.org");

            THEN("the PDU is accepted")
            {
                // Spec MUST: sender domain must match origin. '@alice:example.org'
                // sends from 'example.org' — this is a valid match.
                REQUIRE(decision.accepted);
            }
        }

        WHEN("the expected origin is 'other.example.org' (does not match sender domain)")
        {
            auto const decision =
                merovingian::federation::authorize_federation_pdu(pdu, "other.example.org");

            THEN("the PDU is rejected")
            {
                // Spec MUST: sender's domain MUST match the origin server.
                // A PDU claiming to be from '@alice:example.org' cannot arrive
                // from 'other.example.org' — it must be rejected.
                REQUIRE(!decision.accepted);
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

    GIVEN("a valid m.room.create PDU with depth 0")
    {
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
