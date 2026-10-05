// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/runtime_federation.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("federation_policy", event, fields, severity);
    }

    [[nodiscard]] auto contains_server(std::vector<std::string> const& servers, std::string_view server_name) noexcept
        -> bool
    {
        for (auto const& server : servers)
        {
            if (server == server_name)
            {
                return true;
            }
        }

        return false;
    }

    [[nodiscard]] auto rate_limit_policy_string(http::RateLimitPolicy const& policy) -> std::string
    {
        return std::to_string(policy.max_requests) + "/" + std::to_string(policy.window_seconds) + "s";
    }

} // namespace

auto make_runtime_federation_config(config::Config const& config) -> RuntimeFederationConfig
{
    auto const max_transaction_size = config::parse_size_limit(config.security().federation.max_transaction_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().federation.remote_timeout);
    auto const join_timeout = config::parse_duration_seconds(config.security().federation.join_timeout);
    auto const join_race_deadline = config::parse_duration_seconds(config.security().federation.join_race_deadline);
    auto const join_response_max_size = config::parse_size_limit(config.security().federation.join_response_max_size);
    auto const backfill_response_max_size =
        config::parse_size_limit(config.security().federation.backfill.response_max_size);
    auto const backfill_timeout = config::parse_duration_seconds(config.security().federation.backfill.timeout);
    auto const pending_join_max_size = config::parse_size_limit(config.security().federation.pending_join_max_size);
    // An unparsable TTL yields 0 (negative caching off) rather than a wild
    // value; config validation has already rejected a malformed one by here.
    auto const key_resolution_failure_ttl =
        config::parse_duration_seconds(config.security().federation.key_resolution_failure_ttl);

    return {
        config.security().federation.enabled,
        config.security().federation.default_policy,
        config.security().federation.allowed_servers,
        config.security().federation.denied_servers,
        config.security().federation.require_valid_tls,
        config.security().federation.verify_json_signatures,
        config.security().federation.deny_ip_ranges,
        max_transaction_size.valid ? max_transaction_size.bytes : 0U,
        config.security().federation.max_transaction_pdus,
        config.security().federation.max_transaction_edus,
        config.security().federation.per_origin_transaction_rate,
        config.security().federation.per_origin_pdu_rate,
        config.security().federation.per_origin_edu_rate,
        config.security().federation.per_origin_request_rate,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
        join_timeout.valid ? join_timeout.seconds : 0U,
        config.security().federation.join_parallelism,
        join_race_deadline.valid ? join_race_deadline.seconds : 0U,
        config.security().federation.join_max_candidates,
        config.security().federation.join_state_key_parallelism,
        join_response_max_size.valid ? join_response_max_size.bytes : 0U,
        config.server().server_name,
        config.security().federation.key_resolution_per_ip_rate,
        config.security().federation.key_resolution_max_in_flight,
        key_resolution_failure_ttl.valid ? key_resolution_failure_ttl.seconds : 0U,
        config.security().federation.bad_signature_per_ip_rate,
        config.security().federation.backfill,
        FederationQueryPolicy{
                              .max_backfill_pdus = config.security().federation.query.max_backfill_pdus,
                              .max_missing_events_pdus = config.security().federation.query.max_missing_events_pdus,
                              .max_missing_events_latest = config.security().federation.query.max_missing_events_latest,
                              .max_missing_events_traversal = config.security().federation.query.max_missing_events_traversal,
                              },
        backfill_timeout.valid ? backfill_timeout.seconds : 0U,
        backfill_response_max_size.valid ? backfill_response_max_size.bytes : 0U,
        config.security().federation.accepted_transaction_cache_entries,
        config.security().federation.audit_event_cache_entries,
        config.security().federation.key_resolution_cache_entries,
        config.security().federation.bad_signature_cache_entries,
        config.security().federation.pending_join_max_rooms,
        config.security().federation.pending_join_max_pdus,
        pending_join_max_size.valid ? pending_join_max_size.bytes : 0U,
        config.security().federation.outbound_queue_capacity,
        config.security().federation.outbound_max_retries,
    };
}

auto federation_summary(RuntimeFederationConfig const& config) -> std::string
{
    return "Federation runtime config: enabled=" + std::string{config.enabled ? "true" : "false"} +
           " default_policy=" + config.default_policy +
           " allowed_servers=" + std::to_string(config.allowed_servers.size()) +
           " denied_servers=" + std::to_string(config.denied_servers.size()) +
           " max_transaction_bytes=" + std::to_string(config.max_transaction_bytes) +
           " max_transaction_pdus=" + std::to_string(config.max_transaction_pdus) +
           " max_transaction_edus=" + std::to_string(config.max_transaction_edus) +
           " per_origin_transaction_rate=" + rate_limit_policy_string(config.per_origin_transaction_rate) +
           " per_origin_pdu_rate=" + rate_limit_policy_string(config.per_origin_pdu_rate) +
           " per_origin_edu_rate=" + rate_limit_policy_string(config.per_origin_edu_rate) +
           " per_origin_request_rate=" + rate_limit_policy_string(config.per_origin_request_rate) +
           " remote_timeout_seconds=" + std::to_string(config.remote_timeout_seconds) +
           " join_timeout_seconds=" + std::to_string(config.join_timeout_seconds) +
           " join_parallelism=" + std::to_string(config.join_parallelism) +
           " join_race_deadline_seconds=" + std::to_string(config.join_race_deadline_seconds) +
           " join_max_candidates=" + std::to_string(config.join_max_candidates) +
           " join_state_key_parallelism=" + std::to_string(config.join_state_key_parallelism) +
           " join_response_max_bytes=" + std::to_string(config.join_response_max_bytes) +
           " key_resolution_per_ip_rate=" + rate_limit_policy_string(config.key_resolution_per_ip_rate) +
           " key_resolution_max_in_flight=" + std::to_string(config.key_resolution_max_in_flight) +
           " key_resolution_failure_ttl_seconds=" + std::to_string(config.key_resolution_failure_ttl_seconds) +
           " backfill.max_missing_events=" + std::to_string(config.backfill.max_missing_events) +
           " backfill.max_outbound_calls=" + std::to_string(config.backfill.max_outbound_calls) +
           " backfill.max_state_ids=" + std::to_string(config.backfill.max_state_ids) +
           " backfill.max_auth_chain_ids=" + std::to_string(config.backfill.max_auth_chain_ids) +
           " backfill.max_snapshot_events=" + std::to_string(config.backfill.max_snapshot_events) +
           " backfill.max_snapshot_outbound_calls=" + std::to_string(config.backfill.max_snapshot_outbound_calls) +
           " backfill.max_total_outbound_calls=" + std::to_string(config.backfill.max_total_outbound_calls) +
           " backfill.timeout_seconds=" + std::to_string(config.backfill_timeout_seconds) +
           " query.max_backfill_pdus=" + std::to_string(config.query_policy.max_backfill_pdus) +
           " query.max_missing_events_pdus=" + std::to_string(config.query_policy.max_missing_events_pdus) +
           " query.max_missing_events_latest=" + std::to_string(config.query_policy.max_missing_events_latest) +
           " query.max_missing_events_traversal=" + std::to_string(config.query_policy.max_missing_events_traversal) +
           " backfill_response_max_bytes=" + std::to_string(config.backfill_response_max_bytes) +
           " accepted_transaction_cache_entries=" + std::to_string(config.accepted_transaction_cache_entries) +
           " audit_event_cache_entries=" + std::to_string(config.audit_event_cache_entries) +
           " key_resolution_cache_entries=" + std::to_string(config.key_resolution_cache_entries) +
           " bad_signature_cache_entries=" + std::to_string(config.bad_signature_cache_entries) +
           " bad_signature_per_ip_rate=" + rate_limit_policy_string(config.bad_signature_per_ip_rate) +
           " pending_join_max_rooms=" + std::to_string(config.pending_join_max_rooms) +
           " pending_join_max_pdus=" + std::to_string(config.pending_join_max_pdus) +
           " pending_join_max_bytes=" + std::to_string(config.pending_join_max_bytes) +
           " outbound_queue_capacity=" + std::to_string(config.outbound_queue_capacity) +
           " outbound_max_retries=" + std::to_string(config.outbound_max_retries);
}

auto federation_server_policy(RuntimeFederationConfig const& config, std::string_view server_name)
    -> FederationServerPolicyDecision
{
    auto result = [&]() -> FederationServerPolicyDecision {
        if (!config.enabled)
        {
            return {false, "federation disabled"};
        }
        if (server_name.empty())
        {
            return {false, "remote server name is empty"};
        }
        if (contains_server(config.denied_servers, server_name))
        {
            return {false, "remote server is denied"};
        }
        if (config.default_policy == "deny" && !contains_server(config.allowed_servers, server_name))
        {
            return {false, "remote server is not in federation allow list"};
        }
        return {true, {}};
    }();
    log_diagnostic(result.allowed ? "server_policy.allowed" : "server_policy.denied",
                   {
                       {"server_name", std::string{server_name}, false},
                       {"reason",      result.reason,            false}
    });
    return result;
}

} // namespace merovingian::federation
