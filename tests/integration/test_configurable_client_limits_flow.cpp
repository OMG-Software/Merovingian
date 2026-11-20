// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/sync/SlidingSyncParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

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
    server.client_api.sliding_sync_max_room_subscriptions = 70U;
    server.client_api.sliding_sync_max_required_state_entries = 800U;
    server.client_api.sliding_sync_connections_per_device = 12U;
    return {std::move(server),
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
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
                REQUIRE(started.runtime.limits.sliding_sync.room_subscriptions == 70U);
                REQUIRE(started.runtime.limits.sliding_sync.required_state_entries == 800U);
                REQUIRE(started.runtime.limits.sliding_sync_connections_per_device == 12U);
            }
        }
    }
}

// MSC4186 "Max subscriptions: 100" is a ceiling the configuration may lower but not raise (ADR-0865).
SCENARIO("a sliding sync subscription limit above MSC4186's ceiling acts as the ceiling",
         "[homeserver][limits][sliding-sync]")
{
    GIVEN("an operator configuration allowing 700 sliding sync room subscriptions")
    {
        auto config = make_client_api_config();
        config.server().client_api.sliding_sync_max_room_subscriptions = 700U;

        WHEN("the client server runtime starts")
        {
            auto const started = merovingian::homeserver::start_client_server(config);

            THEN("the runtime allows 100, the MSC4186 maximum, and keeps the other sliding sync limits")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.limits.sliding_sync.room_subscriptions == 100U);
                REQUIRE(started.runtime.limits.sliding_sync.timeline_limit == 250U);
                REQUIRE(started.runtime.limits.sliding_sync.required_state_entries == 800U);
            }
        }
    }
}

SCENARIO("delayed-event runtime limits are copied from server.delayed_events", "[homeserver][limits][delayed-events]")
{
    GIVEN("an operator configuration with non-default delayed-event settings")
    {
        auto config = make_client_api_config();
        config.server().delayed_events.enabled = false;
        config.server().delayed_events.max_delay_ms = 3'600'000U;
        config.server().delayed_events.max_scheduled_per_user = 7U;
        config.server().delayed_events.max_finalised_per_user = 9U;

        WHEN("the client server runtime starts")
        {
            auto const started = merovingian::homeserver::start_client_server(config);

            THEN("the runtime limits hold the configured values")
            {
                REQUIRE(started.started);
                REQUIRE_FALSE(started.runtime.limits.delayed_events_enabled);
                REQUIRE(started.runtime.limits.max_delayed_event_delay_ms == 3'600'000U);
                REQUIRE(started.runtime.limits.max_scheduled_delayed_events_per_user == 7U);
                REQUIRE(started.runtime.limits.max_finalised_delayed_events_per_user == 9U);
            }
        }
    }
}
