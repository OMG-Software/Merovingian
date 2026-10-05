// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <string>
#include <vector>

SCENARIO("Operational limits can be tuned together and require a restart", "[config][operational-limits]")
{
    GIVEN("a deployment policy for a large room and many clients")
    {
        auto const input = std::string{"server.client_api.max_sync_rooms=2000\n"
                                       "server.client_api.max_notifications_retained_per_user=1500\n"
                                       "security.federation.state_resolution.max_state_groups=20\n"
                                       "security.federation.state_resolution.max_events_per_state_group=100000\n"
                                       "security.federation.state_resolution.max_total_state_events=250000\n"
                                       "security.federation.state_resolution.max_conflicted_state_keys=80000\n"
                                       "security.federation.state_resolution.max_mainline_auth_chain_depth=20000\n"
                                       "security.federation.state_resolution.max_auth_chain_walk_events=200000\n"
                                       "server.client_api.max_body_size=2MiB\n"
                                       "server.client_api.sliding_sync_max_timeline_limit=750\n"
                                       "server.http.sync_threads=192\n"
                                       "server.http.max_body_size=2MiB\n"
                                       "security.federation.backfill.max_state_ids=100000\n"
                                       "security.federation.backfill.max_auth_chain_ids=100000\n"
                                       "security.federation.backfill.max_snapshot_events=200000\n"
                                       "security.federation.backfill.max_snapshot_outbound_calls=512\n"
                                       "security.federation.backfill.response_max_size=32MiB\n"
                                       "security.federation.accepted_transaction_cache_entries=60000\n"
                                       "security.federation.pending_join_max_size=8MiB\n"
                                       "server.push.max_pushers_per_delivery=32\n"};

        WHEN("the policy is parsed, validated and compared with the current deployment")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);
            auto const validation = merovingian::config::validate(parsed.config);
            auto const plan = merovingian::config::build_reload_plan(merovingian::config::Config{}, parsed.config);

            THEN("the overrides survive parsing without misleading hot-reload claims")
            {
                auto finding_text = std::string{};
                for (auto const& finding : parsed.findings)
                {
                    finding_text += finding.field + ": " + finding.message + "\n";
                }
                INFO(finding_text);
                REQUIRE(parsed.findings.empty());
                REQUIRE(validation.empty());
                REQUIRE(parsed.config.server().client_api.max_sync_rooms == 2000U);
                REQUIRE(parsed.config.server().client_api.max_notifications_retained_per_user == 1500U);
                REQUIRE(parsed.config.security().federation.state_resolution.max_events_per_state_group == 100000U);
                REQUIRE(parsed.config.security().federation.state_resolution.max_total_state_events == 250000U);
                REQUIRE(parsed.config.security().federation.state_resolution.max_auth_chain_walk_events == 200000U);
                REQUIRE(parsed.config.server().client_api.sliding_sync_max_timeline_limit == 750U);
                REQUIRE(parsed.config.server().http.sync_threads == 192U);
                REQUIRE(parsed.config.security().federation.backfill.max_state_ids == 100000U);
                REQUIRE(parsed.config.security().federation.backfill.max_snapshot_outbound_calls == 512U);
                REQUIRE(parsed.config.server().push.max_pushers_per_delivery == 32U);
                REQUIRE(plan.changes().size() == 20U);
                REQUIRE(plan.reloadable_change_count() == 0U);
                REQUIRE(plan.restart_required_change_count() == 20U);
            }
        }
    }
}

SCENARIO("Operational limits reject disabled bounds, malformed sizes and excessive allocations",
         "[config][operational-limits][boundary]")
{
    GIVEN("an invalid deployment override")
    {
        auto const input = GENERATE(
            "server.client_api.max_sync_rooms=0\n", "server.client_api.max_sync_rooms=4294967296\n",
            "server.client_api.max_notifications_retained_per_user=0\n",
            "server.client_api.max_notifications_retained_per_user=100001\n",
            "security.federation.state_resolution.max_state_groups=0\n",
            "security.federation.state_resolution.max_events_per_state_group=262145\n",
            "security.federation.state_resolution.max_total_state_events=1048577\n",
            "security.federation.state_resolution.max_conflicted_state_keys=0\n",
            "security.federation.state_resolution.max_mainline_auth_chain_depth=100001\n",
            "security.federation.state_resolution.max_auth_chain_walk_events=524289\n",
            "server.client_api.sliding_sync_max_timeline_limit=-1\n", "server.client_api.max_body_size=0MiB\n",
            "server.http.sync_threads=0\n", "server.http.max_header_count=0\n", "server.http.max_header_count=201\n",
            "server.http.max_header_bytes=65537\n", "server.http.max_start_line_bytes=8193\n",
            "security.federation.backfill.max_state_ids=0\n",
            "security.federation.backfill.max_snapshot_outbound_calls=999999\n",
            "security.federation.backfill.response_max_size=unlimited\n",
            "security.federation.backfill.max_total_outbound_calls=0\n", "security.federation.backfill.timeout=0s\n",
            "security.federation.backfill.timeout=301s\n", "security.federation.key_resolution_cache_entries=0\n",
            "security.federation.pending_join_max_size=0\n", "server.push.max_in_flight_deliveries=0\n",
            "security.federation.max_transaction_size=65MiB\n", "appservice.connect_timeout_seconds=0\n",
            "appservice.connect_timeout_seconds=31\n", "appservice.response_max_size=unlimited\n");

        WHEN("the configuration is parsed and validated")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);
            auto const findings = merovingian::config::validate(parsed.config);

            THEN("the operator gets a validation error instead of an unbounded or unusable policy")
            {
                REQUIRE((!parsed.findings.empty() || !findings.empty()));
            }
        }
    }
}

SCENARIO("Federation rate changes report their actual startup lifecycle", "[config][operational-limits][reload]")
{
    GIVEN("a different authenticated peer budget")
    {
        auto current = merovingian::config::Config{};
        auto next = current;
        next.security().federation.per_origin_edu_rate.max_requests += 1U;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("a restart is required because the federation runtime snapshots that budget")
            {
                REQUIRE(plan.restart_required_change_count() == 1U);
                REQUIRE(plan.reloadable_change_count() == 0U);
            }
        }
    }
}
