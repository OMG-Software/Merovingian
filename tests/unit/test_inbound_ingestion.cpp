// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto build_minimal_pdu_object(std::string_view room_id, std::string_view sender,
                                            std::string_view event_type) -> merovingian::canonicaljson::Object
{
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member(
        "content", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "depth", merovingian::canonicaljson::Value{static_cast<std::int64_t>(5)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "origin_server_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1000)}));
    object.push_back(
        merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{std::string{room_id}}));
    object.push_back(
        merovingian::canonicaljson::make_member("sender", merovingian::canonicaljson::Value{std::string{sender}}));
    object.push_back(
        merovingian::canonicaljson::make_member("type", merovingian::canonicaljson::Value{std::string{event_type}}));
    return object;
}

[[nodiscard]] auto serialize_pdu_object(merovingian::canonicaljson::Object object) -> std::string
{
    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(object)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto build_minimal_pdu_json(std::string_view room_id, std::string_view sender,
                                          std::string_view event_type) -> std::string
{
    auto object = build_minimal_pdu_object(room_id, sender, event_type);
    object.push_back(merovingian::canonicaljson::make_member(
        "auth_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "prev_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    return serialize_pdu_object(std::move(object));
}

[[nodiscard]] auto build_minimal_pdu_json_with_events(std::size_t prev_count, std::size_t auth_count) -> std::string
{
    auto object = build_minimal_pdu_object("!room:example.org", "@alice:example.org", "m.room.message");
    auto prev_events = merovingian::canonicaljson::Array{};
    prev_events.reserve(prev_count);
    for (std::size_t i = 0; i < prev_count; ++i)
    {
        prev_events.push_back(
            merovingian::canonicaljson::Value{std::string{"$prev"} + std::to_string(i) + std::string{":example.org"}});
    }
    auto auth_events = merovingian::canonicaljson::Array{};
    auth_events.reserve(auth_count);
    for (std::size_t i = 0; i < auth_count; ++i)
    {
        auth_events.push_back(
            merovingian::canonicaljson::Value{std::string{"$auth"} + std::to_string(i) + std::string{":example.org"}});
    }
    object.push_back(merovingian::canonicaljson::make_member(
        "prev_events", merovingian::canonicaljson::Value{std::move(prev_events)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "auth_events", merovingian::canonicaljson::Value{std::move(auth_events)}));
    return serialize_pdu_object(std::move(object));
}

[[nodiscard]] auto pad_pdu_to_target_size(std::string pdu_json, std::size_t target_size) -> std::string
{
    auto constexpr marker = std::string_view{R"("content":{})"};
    auto constexpr prefix = std::string_view{R"("content":)"};
    auto constexpr wrapper_open = std::string_view{R"({"padding":"})"};
    auto constexpr wrapper_close = std::string_view{"\"}"};
    // Replacing the marker with prefix + wrapper adds this much overhead beyond
    // the original marker.
    auto constexpr overhead = prefix.size() + wrapper_open.size() + wrapper_close.size() - marker.size();

    auto const content_pos = pdu_json.find(marker);
    REQUIRE(content_pos != std::string::npos);

    auto const padding = target_size + 0U > pdu_json.size() + overhead ? target_size - pdu_json.size() - overhead : 0U;
    auto const padded_content = std::string{wrapper_open} + std::string(padding, 'x') + std::string{wrapper_close};
    pdu_json.replace(content_pos, marker.size(), std::string{prefix} + padded_content);
    return pdu_json;
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
            // Spec: SS API v1.19 §m.signing_key_update — sent when a user
            // updates their cross-signing keys. Dropping it as unknown leaves
            // local clients holding a remote user's stale cross-signing identity.
            REQUIRE(merovingian::federation::classify_edu_type("m.signing_key_update") ==
                    merovingian::federation::EduType::signing_key_update);
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
        // Spec: SS API v1.19 §m.typing — content is { room_id, user_id, typing }.
        // (CS API uses user_ids array; SS API uses per-user user_id + bool.)
        auto const content =
            std::string{R"({"room_id":"!room:example.org","user_id":"@alice:example.org","typing":true})"};

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

    GIVEN("an m.signing_key_update payload naming its user")
    {
        // Spec: SS API v1.19 §m.signing_key_update — user_id is required;
        // master_key and self_signing_key are optional CrossSigningKey objects.
        auto const content = std::string{
            R"({"master_key":{"keys":{"ed25519:M":"M"},"usage":["master"],"user_id":"@alice:example.org"},"user_id":"@alice:example.org"})"};

        THEN("the validator accepts it")
        {
            REQUIRE(merovingian::federation::edu_content_is_valid(merovingian::federation::EduType::signing_key_update,
                                                                  content));
        }
    }

    GIVEN("an m.signing_key_update payload with no user_id, or a non-string one")
    {
        auto const missing = std::string{R"({"master_key":{"keys":{"ed25519:M":"M"},"usage":["master"]}})"};
        auto const not_string = std::string{R"({"user_id":7})"};

        THEN("the validator rejects both")
        {
            REQUIRE_FALSE(merovingian::federation::edu_content_is_valid(
                merovingian::federation::EduType::signing_key_update, missing));
            REQUIRE_FALSE(merovingian::federation::edu_content_is_valid(
                merovingian::federation::EduType::signing_key_update, not_string));
        }
    }
}

SCENARIO("EDU envelope parser rejects unknown types and malformed content", "[federation][inbound-ingestion][edu]")
{
    WHEN("a known type with valid content is parsed")
    {
        // Spec: SS API v1.19 §m.typing — content is { room_id, user_id, typing }.
        auto const content =
            std::string{R"({"room_id":"!room:example.org","user_id":"@alice:example.org","typing":true})"};
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

SCENARIO("Inbound ingestion rejects PDUs that exceed the spec event size limit",
         "[federation][inbound-ingestion][limits][m03]")
{
    GIVEN("a PDU whose raw JSON is exactly the 65536-byte limit")
    {
        auto pdu_json =
            pad_pdu_to_target_size(build_minimal_pdu_json("!room:example.org", "@alice:example.org", "m.room.message"),
                                   merovingian::events::max_event_size_bytes);

        WHEN("the PDU is parsed")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

            THEN("it is accepted")
            {
                REQUIRE(envelope.has_value());
                REQUIRE(pdu_json.size() == merovingian::events::max_event_size_bytes);
            }
        }
    }

    GIVEN("a PDU one byte over the 65536-byte limit")
    {
        auto pdu_json =
            pad_pdu_to_target_size(build_minimal_pdu_json("!room:example.org", "@alice:example.org", "m.room.message"),
                                   merovingian::events::max_event_size_bytes + 1U);

        WHEN("the PDU is parsed")
        {
            auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

            THEN("it is rejected before any hashing or authorisation")
            {
                REQUIRE_FALSE(envelope.has_value());
                REQUIRE(pdu_json.size() == merovingian::events::max_event_size_bytes + 1U);
            }
        }
    }
}

SCENARIO("Inbound ingestion enforces the prev_events and auth_events array limits",
         "[federation][inbound-ingestion][limits][m03]")
{
    WHEN("a PDU has exactly the allowed number of prev_events and auth_events")
    {
        auto const pdu_json = build_minimal_pdu_json_with_events(merovingian::events::max_prev_events_per_event,
                                                                 merovingian::events::max_auth_events_per_event);
        auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

        THEN("it is accepted at the boundary")
        {
            REQUIRE(envelope.has_value());
            REQUIRE(envelope->prev_event_ids.size() == merovingian::events::max_prev_events_per_event);
            REQUIRE(envelope->auth_event_ids.size() == merovingian::events::max_auth_events_per_event);
        }
    }

    WHEN("a PDU has one too many prev_events")
    {
        auto const pdu_json = build_minimal_pdu_json_with_events(merovingian::events::max_prev_events_per_event + 1U,
                                                                 merovingian::events::max_auth_events_per_event);
        auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

        THEN("it is rejected before authorisation")
        {
            REQUIRE_FALSE(envelope.has_value());
        }
    }

    WHEN("a PDU has one too many auth_events")
    {
        auto const pdu_json = build_minimal_pdu_json_with_events(merovingian::events::max_prev_events_per_event,
                                                                 merovingian::events::max_auth_events_per_event + 1U);
        auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);

        THEN("it is rejected before authorisation")
        {
            REQUIRE_FALSE(envelope.has_value());
        }
    }
}
