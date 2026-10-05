// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("runtime federation policy carries configured backfill and admission budgets", "[federation][config][limits]")
{
    GIVEN("configuration with explicit tight operational budgets")
    {
        auto config = merovingian::config::Config{};
        auto& federation = config.security().federation;
        federation.query.max_backfill_pdus = 11U;
        federation.query.max_missing_events_pdus = 13U;
        federation.query.max_missing_events_latest = 17U;
        federation.query.max_missing_events_traversal = 19U;
        federation.backfill.max_missing_events = 7U;
        federation.backfill.max_outbound_calls = 9U;
        federation.backfill.max_state_ids = 11U;
        federation.backfill.max_auth_chain_ids = 13U;
        federation.backfill.max_snapshot_events = 17U;
        federation.backfill.max_snapshot_outbound_calls = 19U;
        federation.backfill.max_total_outbound_calls = 21U;
        federation.backfill.response_max_size = "8MiB";
        federation.backfill.timeout = "31s";
        federation.accepted_transaction_cache_entries = 23U;
        federation.audit_event_cache_entries = 29U;
        federation.key_resolution_cache_entries = 31U;
        federation.bad_signature_cache_entries = 37U;
        federation.bad_signature_per_ip_rate = {41U, 60U};
        federation.pending_join_max_rooms = 43U;
        federation.pending_join_max_pdus = 47U;
        federation.pending_join_max_size = "2MiB";
        federation.outbound_queue_capacity = 79U;
        federation.outbound_max_retries = 83U;
        federation.per_origin_transaction_rate = {53U, 60U};
        federation.per_origin_pdu_rate = {59U, 60U};
        federation.per_origin_edu_rate = {61U, 60U};
        federation.per_origin_request_rate = {67U, 60U};
        federation.key_resolution_per_ip_rate = {71U, 60U};
        federation.key_resolution_max_in_flight = 73U;
        federation.key_resolution_failure_ttl = "75s";

        WHEN("the federation runtime policy is built")
        {
            auto const runtime = merovingian::federation::make_runtime_federation_config(config);

            THEN("every bounded-work and admission policy reaches the runtime unchanged")
            {
                REQUIRE(runtime.backfill.max_missing_events == 7U);
                REQUIRE(runtime.backfill.max_outbound_calls == 9U);
                REQUIRE(runtime.backfill.max_state_ids == 11U);
                REQUIRE(runtime.backfill.max_auth_chain_ids == 13U);
                REQUIRE(runtime.backfill.max_snapshot_events == 17U);
                REQUIRE(runtime.backfill.max_snapshot_outbound_calls == 19U);
                REQUIRE(runtime.backfill.max_total_outbound_calls == 21U);
                REQUIRE(runtime.backfill_timeout_seconds == 31U);
                REQUIRE(runtime.backfill_response_max_bytes == 8U * 1024U * 1024U);
                REQUIRE(runtime.query_policy.max_backfill_pdus == 11U);
                REQUIRE(runtime.query_policy.max_missing_events_pdus == 13U);
                REQUIRE(runtime.query_policy.max_missing_events_latest == 17U);
                REQUIRE(runtime.query_policy.max_missing_events_traversal == 19U);
                REQUIRE(runtime.accepted_transaction_cache_entries == 23U);
                REQUIRE(runtime.audit_event_cache_entries == 29U);
                REQUIRE(runtime.key_resolution_cache_entries == 31U);
                REQUIRE(runtime.bad_signature_cache_entries == 37U);
                REQUIRE(runtime.bad_signature_per_ip_rate.max_requests == 41U);
                REQUIRE(runtime.pending_join_max_rooms == 43U);
                REQUIRE(runtime.pending_join_max_pdus == 47U);
                REQUIRE(runtime.pending_join_max_bytes == 2U * 1024U * 1024U);
                REQUIRE(runtime.outbound_queue_capacity == 79U);
                REQUIRE(runtime.outbound_max_retries == 83U);
                REQUIRE(runtime.per_origin_transaction_rate.max_requests == 53U);
                REQUIRE(runtime.per_origin_pdu_rate.max_requests == 59U);
                REQUIRE(runtime.per_origin_edu_rate.max_requests == 61U);
                REQUIRE(runtime.per_origin_request_rate.max_requests == 67U);
                REQUIRE(runtime.key_resolution_per_ip_rate.max_requests == 71U);
                REQUIRE(runtime.key_resolution_max_in_flight == 73U);
                REQUIRE(runtime.key_resolution_failure_ttl_seconds == 75U);
            }
        }
    }
}
