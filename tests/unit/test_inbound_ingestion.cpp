// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto build_minimal_pdu_json(std::string_view room_id, std::string_view sender,
                                          std::string_view event_type) -> std::string
{
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member(
        "auth_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "content", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "depth", merovingian::canonicaljson::Value{static_cast<std::int64_t>(5)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "origin_server_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1000)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "prev_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    object.push_back(
        merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{std::string{room_id}}));
    object.push_back(
        merovingian::canonicaljson::make_member("sender", merovingian::canonicaljson::Value{std::string{sender}}));
    object.push_back(
        merovingian::canonicaljson::make_member("type", merovingian::canonicaljson::Value{std::string{event_type}}));

    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(object)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

} // namespace

SCENARIO("Inbound ingestion parses a federation PDU into its envelope", "[federation][inbound-ingestion][pdu]")
{
    GIVEN("a minimal canonical JSON PDU")
    {
        auto const pdu_json = build_minimal_pdu_json("!room1:example.org", "@alice:example.org", "m.room.message");

        WHEN("the PDU is parsed into the ingestion envelope")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

            THEN("the envelope carries the canonical event identifier and core fields")
            {
                REQUIRE(envelope.has_value());
                REQUIRE(!envelope->event_id.empty());
                REQUIRE(envelope->room_id == "!room1:example.org");
                REQUIRE(envelope->sender == "@alice:example.org");
                REQUIRE(envelope->event_type == "m.room.message");
                REQUIRE(envelope->depth == 5U);
                REQUIRE(envelope->origin_server_ts == 1000);
                REQUIRE(envelope->json == pdu_json);
            }
        }
    }
}

SCENARIO("Inbound ingestion rejects non-JSON PDUs", "[federation][inbound-ingestion][pdu]")
{
    GIVEN("a comma-delimited legacy PDU encoding")
    {
        auto const encoded =
            std::string{"$event1:example.org,!room1:example.org,m.room.message,@alice:example.org,example.org,"
                        "ed25519:auto,signature"};

        WHEN("the legacy encoding is parsed for ingestion")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(encoded);

            THEN("ingestion declines the input because it is not a canonical JSON object")
            {
                REQUIRE_FALSE(envelope.has_value());
            }
        }
    }
}

SCENARIO("EDU classifier recognises the federation-handled types", "[federation][inbound-ingestion][edu]")
{
    WHEN("each well-known EDU type is classified")
    {
        THEN("the dispatcher returns the matching enum")
        {
            REQUIRE(merovingian::federation::classify_edu_type("m.typing") == merovingian::federation::EduType::typing);
            REQUIRE(merovingian::federation::classify_edu_type("m.receipt") ==
                    merovingian::federation::EduType::receipt);
            REQUIRE(merovingian::federation::classify_edu_type("m.presence") ==
                    merovingian::federation::EduType::presence);
            REQUIRE(merovingian::federation::classify_edu_type("m.direct_to_device") ==
                    merovingian::federation::EduType::direct_to_device);
            REQUIRE(merovingian::federation::classify_edu_type("m.device_list_update") ==
                    merovingian::federation::EduType::device_list_update);
        }
    }

    WHEN("an unknown EDU type is classified")
    {
        THEN("the dispatcher reports unknown")
        {
            REQUIRE(merovingian::federation::classify_edu_type("m.custom_thing") ==
                    merovingian::federation::EduType::unknown);
        }
    }
}

SCENARIO("EDU content validators enforce per-type shape", "[federation][inbound-ingestion][edu]")
{
    GIVEN("a valid m.typing content object")
    {
        auto const content = std::string{R"({"room_id":"!room:example.org","user_ids":["@alice:example.org"]})"};

        THEN("the validator accepts it")
        {
            REQUIRE(merovingian::federation::edu_content_is_valid(merovingian::federation::EduType::typing, content));
        }
    }

    GIVEN("an m.typing content missing required fields")
    {
        auto const content = std::string{R"({"room_id":"!room:example.org"})"};

        THEN("the validator rejects it")
        {
            REQUIRE_FALSE(
                merovingian::federation::edu_content_is_valid(merovingian::federation::EduType::typing, content));
        }
    }

    GIVEN("a valid m.direct_to_device payload")
    {
        auto const content =
            std::string{R"({"messages":{},"message_id":"msg1","sender":"@alice:example.org","type":"m.test"})"};

        THEN("the validator accepts it")
        {
            REQUIRE(merovingian::federation::edu_content_is_valid(merovingian::federation::EduType::direct_to_device,
                                                                  content));
        }
    }

    GIVEN("an m.device_list_update payload missing stream_id")
    {
        auto const content = std::string{R"({"device_id":"DEV","user_id":"@alice:example.org"})"};

        THEN("the validator rejects it")
        {
            REQUIRE_FALSE(merovingian::federation::edu_content_is_valid(
                merovingian::federation::EduType::device_list_update, content));
        }
    }
}

SCENARIO("EDU envelope parser rejects unknown types and malformed content", "[federation][inbound-ingestion][edu]")
{
    WHEN("a known type with valid content is parsed")
    {
        auto const content = std::string{R"({"room_id":"!room:example.org","user_ids":["@alice:example.org"]})"};
        auto const envelope =
            merovingian::federation::parse_inbound_edu_envelope("m.typing", "remote.example.org", content);

        THEN("the envelope is produced and the type is classified")
        {
            REQUIRE(envelope.has_value());
            REQUIRE(envelope->type == merovingian::federation::EduType::typing);
            REQUIRE(envelope->edu_type == "m.typing");
            REQUIRE(envelope->origin == "remote.example.org");
        }
    }

    WHEN("an unknown EDU type is parsed")
    {
        auto const envelope =
            merovingian::federation::parse_inbound_edu_envelope("m.unknown_thing", "remote.example.org", "{}");

        THEN("the parser drops the unknown type")
        {
            REQUIRE_FALSE(envelope.has_value());
        }
    }

    WHEN("a known type with malformed content is parsed")
    {
        auto const envelope =
            merovingian::federation::parse_inbound_edu_envelope("m.typing", "remote.example.org", "not-json");

        THEN("the parser rejects the malformed payload")
        {
            REQUIRE_FALSE(envelope.has_value());
        }
    }
}
