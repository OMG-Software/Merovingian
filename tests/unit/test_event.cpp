// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto make_minimal_event_object(std::string_view room_id, std::string_view sender,
                                             std::string_view event_type) -> merovingian::canonicaljson::Object
{
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member(
        "auth_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "content", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
    object.push_back(merovingian::canonicaljson::make_member(
        "depth", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "origin_server_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1)}));
    object.push_back(merovingian::canonicaljson::make_member(
        "prev_events", merovingian::canonicaljson::Value{merovingian::canonicaljson::Array{}}));
    object.push_back(
        merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{std::string{room_id}}));
    object.push_back(
        merovingian::canonicaljson::make_member("sender", merovingian::canonicaljson::Value{std::string{sender}}));
    object.push_back(
        merovingian::canonicaljson::make_member("type", merovingian::canonicaljson::Value{std::string{event_type}}));
    return object;
}

[[nodiscard]] auto make_signatures_object(std::size_t servers, std::size_t keys_per_server)
    -> merovingian::canonicaljson::Object
{
    auto signatures = merovingian::canonicaljson::Object{};
    for (std::size_t s = 0; s < servers; ++s)
    {
        auto server_sigs = merovingian::canonicaljson::Object{};
        for (std::size_t k = 0; k < keys_per_server; ++k)
        {
            auto key_id = std::string{"ed25519:key"} + std::to_string(k);
            server_sigs.push_back(merovingian::canonicaljson::make_member(
                key_id, merovingian::canonicaljson::Value{std::string{"signature"}}));
        }
        auto server_name = std::string{"server"} + std::to_string(s) + ".example.org";
        signatures.push_back(merovingian::canonicaljson::make_member(
            server_name, merovingian::canonicaljson::Value{std::move(server_sigs)}));
    }
    return signatures;
}

[[nodiscard]] auto parse_event_from_object(merovingian::canonicaljson::Object object)
    -> merovingian::events::EventParseResult
{
    auto const serialized = merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{object});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const parsed = merovingian::canonicaljson::parse_lossless(serialized.output);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return merovingian::events::parse_event_envelope(parsed.value);
}

} // namespace

SCENARIO("Event envelope parsing accepts normal signature counts", "[events][signatures][limits]")
{
    GIVEN("a minimal event with one server and one key")
    {
        auto object = make_minimal_event_object("!room:example.org", "@alice:example.org", "m.room.message");
        auto sigs = merovingian::canonicaljson::Object{};
        sigs.push_back(merovingian::canonicaljson::make_member(
            "ed25519:auto", merovingian::canonicaljson::Value{std::string{"signature"}}));
        object.push_back(merovingian::canonicaljson::make_member(
            "signatures", merovingian::canonicaljson::Value{
                              merovingian::canonicaljson::Object{merovingian::canonicaljson::make_member(
                                  "example.org", merovingian::canonicaljson::Value{std::move(sigs)})}}));

        WHEN("the envelope is parsed")
        {
            auto const result = parse_event_from_object(std::move(object));

            THEN("the single signature is accepted")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.event.signatures.size() == 1U);
                REQUIRE(result.event.signatures.front().server_name == "example.org");
                REQUIRE(result.event.signatures.front().key_id == "ed25519:auto");
            }
        }
    }
}

SCENARIO("Event envelope parsing rejects too many signing servers", "[events][signatures][limits]")
{
    GIVEN("an event whose signatures object lists more servers than allowed")
    {
        auto object = make_minimal_event_object("!room:example.org", "@alice:example.org", "m.room.message");
        auto signatures = make_signatures_object(merovingian::events::max_servers_with_signatures + 1U, 1U);
        object.push_back(merovingian::canonicaljson::make_member(
            "signatures", merovingian::canonicaljson::Value{std::move(signatures)}));

        WHEN("the envelope is parsed")
        {
            auto const result = parse_event_from_object(std::move(object));

            THEN("parsing fails closed with a clear resource-limit error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error.find("resource limits") != std::string::npos);
                REQUIRE(result.event.signatures.empty());
            }
        }
    }
}

SCENARIO("Event envelope parsing rejects too many key IDs per server", "[events][signatures][limits]")
{
    GIVEN("an event with one server but too many key IDs")
    {
        auto object = make_minimal_event_object("!room:example.org", "@alice:example.org", "m.room.message");
        auto signatures = make_signatures_object(1U, merovingian::events::max_signatures_per_server + 1U);
        object.push_back(merovingian::canonicaljson::make_member(
            "signatures", merovingian::canonicaljson::Value{std::move(signatures)}));

        WHEN("the envelope is parsed")
        {
            auto const result = parse_event_from_object(std::move(object));

            THEN("parsing fails closed with a clear resource-limit error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error.find("resource limits") != std::string::npos);
                REQUIRE(result.event.signatures.empty());
            }
        }
    }
}

SCENARIO("Event envelope parsing rejects too many total signatures", "[events][signatures][limits]")
{
    GIVEN("an event whose total signature count exceeds the per-event cap")
    {
        auto object = make_minimal_event_object("!room:example.org", "@alice:example.org", "m.room.message");
        // Two servers each carrying just over half the per-event cap guarantees
        // the total exceeds max_signatures_per_event even though neither server
        // exceeds max_signatures_per_server and the server count is within limit.
        auto const half = merovingian::events::max_signatures_per_event / 2U + 1U;
        auto signatures = make_signatures_object(2U, half);
        object.push_back(merovingian::canonicaljson::make_member(
            "signatures", merovingian::canonicaljson::Value{std::move(signatures)}));

        WHEN("the envelope is parsed")
        {
            auto const result = parse_event_from_object(std::move(object));

            THEN("parsing fails closed with a clear resource-limit error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error.find("resource limits") != std::string::npos);
                REQUIRE(result.event.signatures.empty());
            }
        }
    }
}

SCENARIO("Event envelope parsing ignores non-string signature values", "[events][signatures]")
{
    GIVEN("a signature object containing both valid and invalid entries")
    {
        auto object = make_minimal_event_object("!room:example.org", "@alice:example.org", "m.room.message");
        auto server_sigs = merovingian::canonicaljson::Object{};
        server_sigs.push_back(merovingian::canonicaljson::make_member(
            "ed25519:auto", merovingian::canonicaljson::Value{std::string{"signature"}}));
        server_sigs.push_back(merovingian::canonicaljson::make_member(
            "ed25519:null", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
        object.push_back(merovingian::canonicaljson::make_member(
            "signatures", merovingian::canonicaljson::Value{
                              merovingian::canonicaljson::Object{merovingian::canonicaljson::make_member(
                                  "example.org", merovingian::canonicaljson::Value{std::move(server_sigs)})}}));

        WHEN("the envelope is parsed")
        {
            auto const result = parse_event_from_object(std::move(object));

            THEN("only the string signature is kept")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.event.signatures.size() == 1U);
                REQUIRE(result.event.signatures.front().key_id == "ed25519:auto");
            }
        }
    }
}
