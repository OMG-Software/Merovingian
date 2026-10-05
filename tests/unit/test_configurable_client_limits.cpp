// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/sync/sliding_sync_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto make_client_api_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.client_api.max_body_size = "2MiB";
    server.client_api.max_sync_rooms = 60U;
    server.client_api.max_sync_events_per_room = 30U;
    server.client_api.max_search_events_scanned = 12000U;
    server.client_api.max_messages_events_examined = 13000U;
    server.client_api.max_messages_page_size = 400U;
    server.client_api.max_context_events = 80U;
    server.client_api.max_search_page_size = 90U;
    server.client_api.max_search_context_events = 75U;
    server.client_api.max_registration_validation_sessions = 50U;
    server.client_api.max_registration_validation_sessions_per_remote = 5U;
    server.client_api.max_uia_sessions = 70U;
    server.client_api.max_safety_report_rows = 300U;
    server.client_api.max_notifications_page_size = 400U;
    server.client_api.max_relations_page_size = 450U;
    server.client_api.max_public_rooms_page_size = 600U;
    server.client_api.max_hierarchy_rooms = 700U;
    server.client_api.sliding_sync_max_timeline_limit = 250U;
    server.client_api.sliding_sync_max_room_subscriptions = 700U;
    server.client_api.sliding_sync_max_required_state_entries = 800U;
    server.client_api.sliding_sync_connections_per_device = 12U;
    return {std::move(server),
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto required_state(std::size_t count) -> std::string
{
    auto out = std::string{"["};
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "[\"m.room.member\",\"@u" + std::to_string(i) + ":example.org\"]";
    }
    out += ']';
    return out;
}

[[nodiscard]] auto subscriptions(std::size_t count, std::size_t required_state_count = 2U) -> std::string
{
    auto out = std::string{"{\"room_subscriptions\":{"};
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "\"!r" + std::to_string(i) +
               ":example.org\":{\"required_state\":" + required_state(required_state_count) +
               ",\"timeline_limit\":120}";
    }
    out += "}}";
    return out;
}

} // namespace

SCENARIO("client API runtime limits are copied from the server configuration", "[homeserver][limits]")
{
    GIVEN("an operator configuration with non-default client API limits")
    {
        auto config = make_client_api_config();

        WHEN("the client server runtime starts")
        {
            auto const started = merovingian::homeserver::start_client_server(config);

            THEN("the runtime uses the configured body, sync, search, pagination and sliding limits")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.limits.max_body_bytes == 2U * 1024U * 1024U);
                REQUIRE(started.runtime.limits.max_sync_rooms == 60U);
                REQUIRE(started.runtime.limits.max_sync_events_per_room == 30U);
                REQUIRE(started.runtime.limits.max_search_events_scanned == 12000U);
                REQUIRE(started.runtime.limits.max_messages_events_examined == 13000U);
                REQUIRE(started.runtime.limits.max_messages_page_size == 400U);
                REQUIRE(started.runtime.limits.max_context_events == 80U);
                REQUIRE(started.runtime.limits.max_search_page_size == 90U);
                REQUIRE(started.runtime.limits.max_search_context_events == 75U);
                REQUIRE(started.runtime.limits.max_registration_validation_sessions == 50U);
                REQUIRE(started.runtime.limits.max_registration_validation_sessions_per_remote == 5U);
                REQUIRE(started.runtime.limits.max_uia_sessions == 70U);
                REQUIRE(started.runtime.limits.max_safety_report_rows == 300U);
                REQUIRE(started.runtime.limits.max_notifications_page_size == 400U);
                REQUIRE(started.runtime.limits.max_relations_page_size == 450U);
                REQUIRE(started.runtime.limits.max_public_rooms_page_size == 600U);
                REQUIRE(started.runtime.limits.max_hierarchy_rooms == 700U);
                REQUIRE(started.runtime.limits.sliding_sync.timeline_limit == 250U);
                REQUIRE(started.runtime.limits.sliding_sync.room_subscriptions == 700U);
                REQUIRE(started.runtime.limits.sliding_sync.required_state_entries == 800U);
                REQUIRE(started.runtime.limits.sliding_sync_connections_per_device == 12U);
            }
        }
    }
}

SCENARIO("sliding sync parser clamps both timeline surfaces to the supplied policy", "[sync][limits]")
{
    GIVEN("a policy whose timeline ceiling is below a list and subscription request")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 2U;
        auto const body =
            R"({"lists":{"a":{"ranges":[[0,1]],"timeline_limit":5}},"room_subscriptions":{"!r:example.org":{"timeline_limit":4}}})";

        WHEN("the request is parsed under that policy")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);

            THEN("both requested timeline sizes are capped by the configured ceiling")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->lists.at("a").timeline_limit == 2U);
                REQUIRE(parsed->room_subscriptions.at("!r:example.org").timeline_limit == 2U);
            }
        }
    }
}

SCENARIO("sliding sync parser honors policy values above the compiled compatibility defaults", "[sync][limits]")
{
    GIVEN("a configured timeline ceiling of 150 and a request for 120 events")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 150U;
        auto const body = R"({"room_subscriptions":{"!r:example.org":{"timeline_limit":120}}})";

        WHEN("the request is parsed under that policy")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);

            THEN("the configured higher ceiling is honored")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->room_subscriptions.at("!r:example.org").timeline_limit == 120U);
            }
        }
    }
}

SCENARIO("sliding sync count limits can be raised above their compatibility defaults", "[sync][limits]")
{
    GIVEN("configured subscription and required-state ceilings above 256")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 300U;
        limits.required_state_entries = 300U;

        WHEN("a request uses 257 subscriptions and 257 required-state pairs")
        {
            auto const many_subscriptions =
                merovingian::sync::parse_sliding_sync_request(subscriptions(257U, 0U), limits);
            auto const many_state_pairs = merovingian::sync::parse_sliding_sync_request(
                std::string{"{\"room_subscriptions\":{\"!r:example.org\":{\"required_state\":"} + required_state(257U) +
                    "}}}",
                limits);

            THEN("the configured higher count ceilings admit both requests")
            {
                REQUIRE(many_subscriptions.has_value());
                REQUIRE_FALSE(
                    merovingian::sync::sliding_sync_request_limit_violation(*many_subscriptions, limits).has_value());
                REQUIRE(many_state_pairs.has_value());
                REQUIRE_FALSE(
                    merovingian::sync::sliding_sync_request_limit_violation(*many_state_pairs, limits).has_value());
            }
        }
    }
}

SCENARIO("sliding sync admission uses configured subscription and state pair ceilings", "[sync][limits]")
{
    GIVEN("a policy that permits two subscriptions with two required-state pairs each")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 2U;
        limits.required_state_entries = 2U;
        auto const parsed = merovingian::sync::parse_sliding_sync_request(subscriptions(3U), limits);
        REQUIRE(parsed.has_value());

        WHEN("the parsed request exceeds the subscription policy")
        {
            auto const violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits);

            THEN("the policy checker reports the subscription bound")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many room_subscriptions");
            }
        }
    }
}

SCENARIO("sliding sync required-state checks use configured policy and retain default compatibility", "[sync][limits]")
{
    GIVEN("one subscription with three required-state pairs and a configured cap of two")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.room_subscriptions = 4U;
        limits.required_state_entries = 2U;
        auto body = std::string{"{\"room_subscriptions\":{\"!r:example.org\":{\"required_state\":"} +
                    required_state(3U) + "}}}";
        auto const parsed = merovingian::sync::parse_sliding_sync_request(body, limits);
        REQUIRE(parsed.has_value());

        WHEN("the configured required-state policy is applied")
        {
            auto const violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits);

            THEN("the request is rejected by the supplied cap while default calls retain the old ceiling")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many required_state entries in a room subscription");
                auto const default_violation = merovingian::sync::sliding_sync_request_limit_violation(*parsed);
                REQUIRE_FALSE(default_violation.has_value());
            }
        }
    }
}

SCENARIO("sliding sync position parsing remains independent of resource policy", "[sync][limits]")
{
    GIVEN("a valid encoded position and a restrictive empty-work policy")
    {
        auto limits = merovingian::sync::SlidingSyncLimits{};
        limits.timeline_limit = 0U;
        limits.room_subscriptions = 0U;
        limits.required_state_entries = 0U;

        WHEN("request limits and the position are interpreted separately")
        {
            auto const parsed = merovingian::sync::parse_sliding_sync_request(R"({"pos":"1|2|3"})", limits);
            auto const pos = merovingian::sync::parse_sliding_sync_pos("/sync?pos=1_2_3");

            THEN("the request limits do not alter position decoding")
            {
                REQUIRE(parsed.has_value());
                REQUIRE_FALSE(merovingian::sync::sliding_sync_request_limit_violation(*parsed, limits).has_value());
                REQUIRE(pos.has_value());
                REQUIRE(pos->event_ordering == 1U);
            }
        }
    }
}
