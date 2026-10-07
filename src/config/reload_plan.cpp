// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/reload_plan.hpp"

#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace merovingian::config
{
namespace
{

    auto add_change(ReloadPlan& plan, std::string const& key) -> void
    {
        plan.add_change({key, reload_policy_for_key(key)});
    }

    // Emit one change per added, removed, or altered entry of a string-keyed
    // map-valued config block (client_rate_limits.per_*, log_modules.*).
    template <typename MapType>
    auto diff_keyed_map(ReloadPlan& plan, std::string const& prefix, MapType const& current, MapType const& next)
        -> void
    {
        for (auto const& [key, value] : current)
        {
            auto const it = next.find(key);
            if (it == next.end() || !(it->second == value))
            {
                add_change(plan, prefix + key);
            }
        }
        for (auto const& [key, value] : next)
        {
            std::ignore = value;
            if (!current.contains(key))
            {
                add_change(plan, prefix + key);
            }
        }
    }

} // namespace

auto ReloadPlan::changes() const noexcept -> std::vector<ReloadChange> const&
{
    return m_changes;
}

auto ReloadPlan::add_change(ReloadChange change) -> void
{
    m_changes.push_back(std::move(change));
}

auto ReloadPlan::has_changes() const noexcept -> bool
{
    return !m_changes.empty();
}

auto ReloadPlan::has_restart_required_changes() const noexcept -> bool
{
    return restart_required_change_count() > 0U;
}

auto ReloadPlan::reloadable_change_count() const noexcept -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& change : m_changes)
    {
        if (change.policy == ReloadPolicy::reloadable)
        {
            ++count;
        }
    }

    return count;
}

auto ReloadPlan::restart_required_change_count() const noexcept -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& change : m_changes)
    {
        if (change.policy == ReloadPolicy::restart_required)
        {
            ++count;
        }
    }

    return count;
}

auto build_reload_plan(Config const& current, Config const& next) -> ReloadPlan
{
    auto plan = ReloadPlan{};

    if (current.server().server_name != next.server().server_name)
    {
        add_change(plan, "server.name");
    }
    if (current.server().public_baseurl != next.server().public_baseurl)
    {
        add_change(plan, "server.public_baseurl");
    }
    if (current.server().trusted_proxies != next.server().trusted_proxies)
    {
        add_change(plan, "server.trusted_proxies");
    }

    // The HTTP transport block is wired when the listeners start; every key
    // is restart-required (reload_policy.cpp), but an edit must still show.
    auto const& current_http = current.server().http;
    auto const& next_http = next.server().http;
    if (current_http.keep_alive != next_http.keep_alive)
    {
        add_change(plan, "server.http.keep_alive");
    }
    if (current_http.keep_alive_idle_seconds != next_http.keep_alive_idle_seconds)
    {
        add_change(plan, "server.http.keep_alive_idle_seconds");
    }
    if (current_http.keep_alive_max_connections != next_http.keep_alive_max_connections)
    {
        add_change(plan, "server.http.keep_alive_max_connections");
    }
    if (current_http.max_connections_per_ip != next_http.max_connections_per_ip)
    {
        add_change(plan, "server.http.max_connections_per_ip");
    }
    if (current_http.ipv6_client_prefix_length != next_http.ipv6_client_prefix_length)
    {
        add_change(plan, "server.http.ipv6_client_prefix_length");
    }
    if (current_http.request_threads != next_http.request_threads)
    {
        add_change(plan, "server.http.request_threads");
    }

    if (current.listeners().client.bind != next.listeners().client.bind)
    {
        add_change(plan, "listeners.client.bind");
    }
    if (current.listeners().max_queued_connections != next.listeners().max_queued_connections)
    {
        add_change(plan, "listeners.max_queued_connections");
    }
    if (current.listeners().client.tls != next.listeners().client.tls)
    {
        add_change(plan, "listeners.client.tls");
    }
    if (current.listeners().client.tls_certificate_file != next.listeners().client.tls_certificate_file)
    {
        add_change(plan, "listeners.client.tls_certificate_file");
    }
    if (current.listeners().client.tls_private_key_file != next.listeners().client.tls_private_key_file)
    {
        add_change(plan, "listeners.client.tls_private_key_file");
    }
    if (current.listeners().federation.bind != next.listeners().federation.bind)
    {
        add_change(plan, "listeners.federation.bind");
    }
    if (current.listeners().federation.tls != next.listeners().federation.tls)
    {
        add_change(plan, "listeners.federation.tls");
    }
    if (current.listeners().federation.tls_certificate_file != next.listeners().federation.tls_certificate_file)
    {
        add_change(plan, "listeners.federation.tls_certificate_file");
    }
    if (current.listeners().federation.tls_private_key_file != next.listeners().federation.tls_private_key_file)
    {
        add_change(plan, "listeners.federation.tls_private_key_file");
    }

    if (current.database().uri_file != next.database().uri_file)
    {
        add_change(plan, "database.uri_file");
    }
    if (current.database().role != next.database().role)
    {
        add_change(plan, "database.role");
    }
    // Role names take effect on connect, so a change to either is restart-required
    // like the rest of this block. Omitting them would let an operator edit the
    // separation and see "no changes", believing it had been applied.
    if (current.database().migration_role != next.database().migration_role)
    {
        add_change(plan, "database.migration_role");
    }
    if (current.database().runtime_role != next.database().runtime_role)
    {
        add_change(plan, "database.runtime_role");
    }
    if (current.database().pool_size != next.database().pool_size)
    {
        add_change(plan, "database.pool_size");
    }

    if (current.security().registration.enabled != next.security().registration.enabled)
    {
        add_change(plan, "security.registration.enabled");
    }
    if (current.security().registration.require_token != next.security().registration.require_token)
    {
        add_change(plan, "security.registration.require_token");
    }
    if (current.security().registration.token_file != next.security().registration.token_file)
    {
        add_change(plan, "security.registration.token_file");
    }

    if (current.security().encryption.default_for_new_rooms != next.security().encryption.default_for_new_rooms)
    {
        add_change(plan, "security.encryption.default_for_new_rooms");
    }
    if (current.security().encryption.require_for_direct_messages !=
        next.security().encryption.require_for_direct_messages)
    {
        add_change(plan, "security.encryption.require_for_direct_messages");
    }
    if (current.security().encryption.require_for_private_rooms != next.security().encryption.require_for_private_rooms)
    {
        add_change(plan, "security.encryption.require_for_private_rooms");
    }
    if (current.security().encryption.allow_unencrypted_public_rooms !=
        next.security().encryption.allow_unencrypted_public_rooms)
    {
        add_change(plan, "security.encryption.allow_unencrypted_public_rooms");
    }
    if (current.security().encryption.block_unencrypted_federated_private_rooms !=
        next.security().encryption.block_unencrypted_federated_private_rooms)
    {
        add_change(plan, "security.encryption.block_unencrypted_federated_private_rooms");
    }

    if (current.security().federation.enabled != next.security().federation.enabled)
    {
        add_change(plan, "security.federation.enabled");
    }
    if (current.security().federation.default_policy != next.security().federation.default_policy)
    {
        add_change(plan, "security.federation.default_policy");
    }
    if (current.security().federation.allowed_servers != next.security().federation.allowed_servers)
    {
        add_change(plan, "security.federation.allowed_servers");
    }
    if (current.security().federation.denied_servers != next.security().federation.denied_servers)
    {
        add_change(plan, "security.federation.denied_servers");
    }
    if (current.security().federation.require_valid_tls != next.security().federation.require_valid_tls)
    {
        add_change(plan, "security.federation.require_valid_tls");
    }
    if (current.security().federation.verify_json_signatures != next.security().federation.verify_json_signatures)
    {
        add_change(plan, "security.federation.verify_json_signatures");
    }
    if (current.security().federation.deny_ip_ranges != next.security().federation.deny_ip_ranges)
    {
        add_change(plan, "security.federation.deny_ip_ranges");
    }
    if (current.security().federation.max_transaction_size != next.security().federation.max_transaction_size)
    {
        add_change(plan, "security.federation.max_transaction_size");
    }
    if (current.security().federation.max_transaction_pdus != next.security().federation.max_transaction_pdus)
    {
        add_change(plan, "security.federation.max_transaction_pdus");
    }
    if (current.security().federation.max_transaction_edus != next.security().federation.max_transaction_edus)
    {
        add_change(plan, "security.federation.max_transaction_edus");
    }
    if (current.security().federation.per_origin_transaction_rate.max_requests !=
            next.security().federation.per_origin_transaction_rate.max_requests ||
        current.security().federation.per_origin_transaction_rate.window_seconds !=
            next.security().federation.per_origin_transaction_rate.window_seconds)
    {
        add_change(plan, "security.federation.per_origin_transaction_rate");
    }
    if (current.security().federation.per_origin_pdu_rate.max_requests !=
            next.security().federation.per_origin_pdu_rate.max_requests ||
        current.security().federation.per_origin_pdu_rate.window_seconds !=
            next.security().federation.per_origin_pdu_rate.window_seconds)
    {
        add_change(plan, "security.federation.per_origin_pdu_rate");
    }
    if (current.security().federation.per_origin_edu_rate.max_requests !=
            next.security().federation.per_origin_edu_rate.max_requests ||
        current.security().federation.per_origin_edu_rate.window_seconds !=
            next.security().federation.per_origin_edu_rate.window_seconds)
    {
        add_change(plan, "security.federation.per_origin_edu_rate");
    }
    if (current.security().federation.per_origin_request_rate.max_requests !=
            next.security().federation.per_origin_request_rate.max_requests ||
        current.security().federation.per_origin_request_rate.window_seconds !=
            next.security().federation.per_origin_request_rate.window_seconds)
    {
        add_change(plan, "security.federation.per_origin_request_rate");
    }
    if (current.security().federation.key_resolution_per_ip_rate.max_requests !=
            next.security().federation.key_resolution_per_ip_rate.max_requests ||
        current.security().federation.key_resolution_per_ip_rate.window_seconds !=
            next.security().federation.key_resolution_per_ip_rate.window_seconds)
    {
        add_change(plan, "security.federation.key_resolution_per_ip_rate");
    }
    if (current.security().federation.key_resolution_max_in_flight !=
        next.security().federation.key_resolution_max_in_flight)
    {
        add_change(plan, "security.federation.key_resolution_max_in_flight");
    }
    if (current.security().federation.key_resolution_failure_ttl !=
        next.security().federation.key_resolution_failure_ttl)
    {
        add_change(plan, "security.federation.key_resolution_failure_ttl");
    }
    if (current.security().federation.remote_timeout != next.security().federation.remote_timeout)
    {
        add_change(plan, "security.federation.remote_timeout");
    }
    if (current.security().federation.join_timeout != next.security().federation.join_timeout)
    {
        add_change(plan, "security.federation.join_timeout");
    }
    if (current.security().federation.join_parallelism != next.security().federation.join_parallelism)
    {
        add_change(plan, "security.federation.join_parallelism");
    }
    if (current.security().federation.join_race_deadline != next.security().federation.join_race_deadline)
    {
        add_change(plan, "security.federation.join_race_deadline");
    }
    if (current.security().federation.join_max_candidates != next.security().federation.join_max_candidates)
    {
        add_change(plan, "security.federation.join_max_candidates");
    }
    if (current.security().federation.join_state_key_parallelism !=
        next.security().federation.join_state_key_parallelism)
    {
        add_change(plan, "security.federation.join_state_key_parallelism");
    }
    if (current.security().federation.join_response_max_size != next.security().federation.join_response_max_size)
    {
        add_change(plan, "security.federation.join_response_max_size");
    }

    if (current.security().media.max_upload_size != next.security().media.max_upload_size)
    {
        add_change(plan, "security.media.max_upload_size");
    }
    if (current.security().media.quarantine_unknown_mime != next.security().media.quarantine_unknown_mime)
    {
        add_change(plan, "security.media.quarantine_unknown_mime");
    }
    if (current.security().media.enable_av_scanner != next.security().media.enable_av_scanner)
    {
        add_change(plan, "security.media.enable_av_scanner");
    }
    if (current.security().media.local_upload_policy != next.security().media.local_upload_policy)
    {
        add_change(plan, "security.media.local_upload_policy");
    }
    if (current.security().media.remote_fetch_media_policy != next.security().media.remote_fetch_media_policy)
    {
        add_change(plan, "security.media.remote_fetch_media_policy");
    }
    if (current.security().media.block_private_ip_fetches != next.security().media.block_private_ip_fetches)
    {
        add_change(plan, "security.media.block_private_ip_fetches");
    }
    if (current.security().media.remote_fetch_timeout != next.security().media.remote_fetch_timeout)
    {
        add_change(plan, "security.media.remote_fetch_timeout");
    }
    if (current.security().media.remote_fetch_enabled != next.security().media.remote_fetch_enabled)
    {
        add_change(plan, "security.media.remote_fetch_enabled");
    }
    if (current.security().media.decode_in_sandbox != next.security().media.decode_in_sandbox)
    {
        add_change(plan, "security.media.decode_in_sandbox");
    }
    if (current.security().media.remote_media_cache_ttl_seconds != next.security().media.remote_media_cache_ttl_seconds)
    {
        add_change(plan, "security.media.remote_media_cache_ttl_seconds");
    }
    if (current.security().media.max_total_size != next.security().media.max_total_size)
    {
        add_change(plan, "security.media.max_total_size");
    }
    if (current.security().media.max_size_per_user != next.security().media.max_size_per_user)
    {
        add_change(plan, "security.media.max_size_per_user");
    }
    if (current.security().media.max_records != next.security().media.max_records)
    {
        add_change(plan, "security.media.max_records");
    }
    if (current.security().media.remote_media_cache_max_size != next.security().media.remote_media_cache_max_size)
    {
        add_change(plan, "security.media.remote_media_cache_max_size");
    }
    if (current.security().media.remote_media_cache_max_entries != next.security().media.remote_media_cache_max_entries)
    {
        add_change(plan, "security.media.remote_media_cache_max_entries");
    }

    if (current.security().logging.redact_tokens != next.security().logging.redact_tokens)
    {
        add_change(plan, "security.logging.redact_tokens");
    }
    if (current.security().logging.redact_event_content != next.security().logging.redact_event_content)
    {
        add_change(plan, "security.logging.redact_event_content");
    }
    if (current.security().logging.structured != next.security().logging.structured)
    {
        add_change(plan, "security.logging.structured");
    }

    // #421: the blocks below previously produced no diff at all, so an edit
    // to any of these keys was reported as "no changes" and silently dropped.

    if (current.server().cors.allowed_origins != next.server().cors.allowed_origins)
    {
        add_change(plan, "server.cors.allowed_origins");
    }
    if (current.server().cors.max_age != next.server().cors.max_age)
    {
        add_change(plan, "server.cors.max_age");
    }
    if (current.server().cors.allow_credentials != next.server().cors.allow_credentials)
    {
        add_change(plan, "server.cors.allow_credentials");
    }
    if (current.server().cors.allow_methods != next.server().cors.allow_methods)
    {
        add_change(plan, "server.cors.allow_methods");
    }
    if (current.server().cors.allow_headers != next.server().cors.allow_headers)
    {
        add_change(plan, "server.cors.allow_headers");
    }

    if (current.server().turn.server != next.server().turn.server)
    {
        add_change(plan, "server.turn.server");
    }
    if (current.server().turn.username != next.server().turn.username)
    {
        add_change(plan, "server.turn.username");
    }
    if (current.server().turn.password != next.server().turn.password)
    {
        add_change(plan, "server.turn.password");
    }
    if (current.server().turn.ttl_seconds != next.server().turn.ttl_seconds)
    {
        add_change(plan, "server.turn.ttl_seconds");
    }

    // Identity Service API. Unlike the OIDC block (which has no reload diff —
    // issue #421), every identity_server field is diffed so a hot-reload that
    // changes the trusted-IS allowlist or timeouts is detected. All changes
    // are restart_required (see reload_policy.cpp): the outbound IS client and
    // cached resolver are built at startup.
    if (current.server().identity_server.trusted_servers != next.server().identity_server.trusted_servers)
    {
        add_change(plan, "server.identity_server.trusted_servers");
    }
    if (current.server().identity_server.default_server != next.server().identity_server.default_server)
    {
        add_change(plan, "server.identity_server.default_server");
    }
    if (current.server().identity_server.allowed_bind_domains != next.server().identity_server.allowed_bind_domains)
    {
        add_change(plan, "server.identity_server.allowed_bind_domains");
    }
    if (current.server().identity_server.connect_timeout_seconds !=
        next.server().identity_server.connect_timeout_seconds)
    {
        add_change(plan, "server.identity_server.connect_timeout_seconds");
    }
    if (current.server().identity_server.total_timeout_seconds != next.server().identity_server.total_timeout_seconds)
    {
        add_change(plan, "server.identity_server.total_timeout_seconds");
    }

    // Push Gateway API. Same reasoning as the identity_server block above:
    // every field is diffed and every change is restart_required (see
    // reload_policy.cpp) because the outbound push client is built at startup.
    if (current.server().push.enabled != next.server().push.enabled)
    {
        add_change(plan, "server.push.enabled");
    }
    if (current.server().push.connect_timeout_seconds != next.server().push.connect_timeout_seconds)
    {
        add_change(plan, "server.push.connect_timeout_seconds");
    }
    if (current.server().push.total_timeout_seconds != next.server().push.total_timeout_seconds)
    {
        add_change(plan, "server.push.total_timeout_seconds");
    }

    if (current.security().secrets.master_key_file != next.security().secrets.master_key_file)
    {
        add_change(plan, "security.secrets.master_key_file");
    }

    if (current.security().trust_safety.enabled != next.security().trust_safety.enabled)
    {
        add_change(plan, "security.trust_safety.enabled");
    }
    if (current.security().trust_safety.policy_server_url != next.security().trust_safety.policy_server_url)
    {
        add_change(plan, "security.trust_safety.policy_server_url");
    }
    if (current.security().trust_safety.policy_server_timeout != next.security().trust_safety.policy_server_timeout)
    {
        add_change(plan, "security.trust_safety.policy_server_timeout");
    }
    if (current.security().trust_safety.policy_server_allow_without_result !=
        next.security().trust_safety.policy_server_allow_without_result)
    {
        add_change(plan, "security.trust_safety.policy_server_allow_without_result");
    }

    if (current.security().access_token_lifetime_ms != next.security().access_token_lifetime_ms)
    {
        add_change(plan, "security.access_token_lifetime_ms");
    }
    if (current.security().refresh_token_lifetime_ms != next.security().refresh_token_lifetime_ms)
    {
        add_change(plan, "security.refresh_token_lifetime_ms");
    }

    if (current.federation_worker().request_timeout_seconds != next.federation_worker().request_timeout_seconds)
    {
        add_change(plan, "federation.worker.request_timeout_seconds");
    }
    if (current.federation_worker().ipc_max_in_flight_requests != next.federation_worker().ipc_max_in_flight_requests)
    {
        add_change(plan, "federation.worker.ipc_max_in_flight_requests");
    }
    if (current.federation_worker().ipc_max_dispatch_queue_count !=
        next.federation_worker().ipc_max_dispatch_queue_count)
    {
        add_change(plan, "federation.worker.ipc_max_dispatch_queue_count");
    }
    if (current.federation_worker().ipc_max_dispatch_queue_bytes !=
        next.federation_worker().ipc_max_dispatch_queue_bytes)
    {
        add_change(plan, "federation.worker.ipc_max_dispatch_queue_bytes");
    }
    if (current.federation_worker().threads != next.federation_worker().threads)
    {
        add_change(plan, "federation.worker.threads");
    }
    if (current.federation_worker().relay_threads != next.federation_worker().relay_threads)
    {
        add_change(plan, "federation.worker.relay_threads");
    }
    if (current.federation_worker().shards != next.federation_worker().shards)
    {
        add_change(plan, "federation.worker.shards");
    }
    if (current.federation_worker().worker_binary != next.federation_worker().worker_binary)
    {
        add_change(plan, "federation.worker.binary");
    }
    if (current.federation_worker().apply_hardening != next.federation_worker().apply_hardening)
    {
        add_change(plan, "federation.worker.apply_hardening");
    }
    if (current.federation_worker().database_uri_file != next.federation_worker().database_uri_file)
    {
        add_change(plan, "federation.worker.database_uri_file");
    }
    if (current.federation_worker().allow_shared_database_credentials !=
        next.federation_worker().allow_shared_database_credentials)
    {
        add_change(plan, "federation.worker.allow_shared_database_credentials");
    }
    if (current.federation_worker().allow_without_landlock != next.federation_worker().allow_without_landlock)
    {
        add_change(plan, "federation.worker.allow_without_landlock");
    }

    if (current.appservice().registration_files != next.appservice().registration_files)
    {
        add_change(plan, "appservice.registration_files");
    }

    if (!(current.client_rate_limits().default_per_ip == next.client_rate_limits().default_per_ip))
    {
        add_change(plan, "client_rate_limits.default_per_ip");
    }
    diff_keyed_map(plan, "client_rate_limits.per_ip.", current.client_rate_limits().per_ip,
                   next.client_rate_limits().per_ip);
    diff_keyed_map(plan, "client_rate_limits.per_user.", current.client_rate_limits().per_user,
                   next.client_rate_limits().per_user);
    diff_keyed_map(plan, "client_rate_limits.tier.", current.client_rate_limits().tier, next.client_rate_limits().tier);
    diff_keyed_map(plan, "log_modules.", current.log_modules().levels, next.log_modules().levels);

    if (current.server().client_api.max_sync_rooms != next.server().client_api.max_sync_rooms)
    {
        add_change(plan, "server.client_api.max_sync_rooms");
    }
    if (current.server().client_api.max_sync_events_per_room != next.server().client_api.max_sync_events_per_room)
    {
        add_change(plan, "server.client_api.max_sync_events_per_room");
    }
    if (current.server().client_api.max_search_events_scanned != next.server().client_api.max_search_events_scanned)
    {
        add_change(plan, "server.client_api.max_search_events_scanned");
    }
    if (current.server().client_api.max_messages_events_examined !=
        next.server().client_api.max_messages_events_examined)
    {
        add_change(plan, "server.client_api.max_messages_events_examined");
    }
    if (current.server().client_api.max_messages_page_size != next.server().client_api.max_messages_page_size)
    {
        add_change(plan, "server.client_api.max_messages_page_size");
    }
    if (current.server().client_api.max_context_events != next.server().client_api.max_context_events)
    {
        add_change(plan, "server.client_api.max_context_events");
    }
    if (current.server().client_api.max_search_page_size != next.server().client_api.max_search_page_size)
    {
        add_change(plan, "server.client_api.max_search_page_size");
    }
    if (current.server().client_api.max_search_context_events != next.server().client_api.max_search_context_events)
    {
        add_change(plan, "server.client_api.max_search_context_events");
    }
    if (current.server().client_api.sliding_sync_max_timeline_limit !=
        next.server().client_api.sliding_sync_max_timeline_limit)
    {
        add_change(plan, "server.client_api.sliding_sync_max_timeline_limit");
    }
    if (current.server().client_api.sliding_sync_max_room_subscriptions !=
        next.server().client_api.sliding_sync_max_room_subscriptions)
    {
        add_change(plan, "server.client_api.sliding_sync_max_room_subscriptions");
    }
    if (current.server().client_api.sliding_sync_max_required_state_entries !=
        next.server().client_api.sliding_sync_max_required_state_entries)
    {
        add_change(plan, "server.client_api.sliding_sync_max_required_state_entries");
    }
    if (current.server().client_api.sliding_sync_connections_per_device !=
        next.server().client_api.sliding_sync_connections_per_device)
    {
        add_change(plan, "server.client_api.sliding_sync_connections_per_device");
    }
    if (current.server().http.sync_threads != next.server().http.sync_threads)
    {
        add_change(plan, "server.http.sync_threads");
    }
    if (current.server().http.sync_max_in_flight != next.server().http.sync_max_in_flight)
    {
        add_change(plan, "server.http.sync_max_in_flight");
    }
    if (current.server().http.sync_max_per_user != next.server().http.sync_max_per_user)
    {
        add_change(plan, "server.http.sync_max_per_user");
    }
    if (current.server().http.sync_max_per_device != next.server().http.sync_max_per_device)
    {
        add_change(plan, "server.http.sync_max_per_device");
    }
    if (current.server().http.media_fetch_threads != next.server().http.media_fetch_threads)
    {
        add_change(plan, "server.http.media_fetch_threads");
    }
    if (current.server().http.media_fetch_max_in_flight != next.server().http.media_fetch_max_in_flight)
    {
        add_change(plan, "server.http.media_fetch_max_in_flight");
    }
    if (current.server().http.media_fetch_max_per_client != next.server().http.media_fetch_max_per_client)
    {
        add_change(plan, "server.http.media_fetch_max_per_client");
    }
    if (current.server().http.max_start_line_bytes != next.server().http.max_start_line_bytes)
    {
        add_change(plan, "server.http.max_start_line_bytes");
    }
    if (current.server().http.max_header_bytes != next.server().http.max_header_bytes)
    {
        add_change(plan, "server.http.max_header_bytes");
    }
    if (current.server().http.max_header_count != next.server().http.max_header_count)
    {
        add_change(plan, "server.http.max_header_count");
    }
    if (current.security().federation.backfill.max_missing_events !=
        next.security().federation.backfill.max_missing_events)
    {
        add_change(plan, "security.federation.backfill.max_missing_events");
    }
    if (current.security().federation.backfill.max_outbound_calls !=
        next.security().federation.backfill.max_outbound_calls)
    {
        add_change(plan, "security.federation.backfill.max_outbound_calls");
    }
    if (current.security().federation.backfill.max_state_ids != next.security().federation.backfill.max_state_ids)
    {
        add_change(plan, "security.federation.backfill.max_state_ids");
    }
    if (current.security().federation.backfill.max_auth_chain_ids !=
        next.security().federation.backfill.max_auth_chain_ids)
    {
        add_change(plan, "security.federation.backfill.max_auth_chain_ids");
    }
    if (current.security().federation.backfill.max_snapshot_events !=
        next.security().federation.backfill.max_snapshot_events)
    {
        add_change(plan, "security.federation.backfill.max_snapshot_events");
    }
    if (current.security().federation.backfill.max_snapshot_outbound_calls !=
        next.security().federation.backfill.max_snapshot_outbound_calls)
    {
        add_change(plan, "security.federation.backfill.max_snapshot_outbound_calls");
    }
    if (current.security().federation.accepted_transaction_cache_entries !=
        next.security().federation.accepted_transaction_cache_entries)
    {
        add_change(plan, "security.federation.accepted_transaction_cache_entries");
    }
    if (current.security().federation.audit_event_cache_entries != next.security().federation.audit_event_cache_entries)
    {
        add_change(plan, "security.federation.audit_event_cache_entries");
    }
    if (current.security().federation.key_resolution_cache_entries !=
        next.security().federation.key_resolution_cache_entries)
    {
        add_change(plan, "security.federation.key_resolution_cache_entries");
    }
    if (current.security().federation.bad_signature_cache_entries !=
        next.security().federation.bad_signature_cache_entries)
    {
        add_change(plan, "security.federation.bad_signature_cache_entries");
    }
    if (current.security().federation.pending_join_max_rooms != next.security().federation.pending_join_max_rooms)
    {
        add_change(plan, "security.federation.pending_join_max_rooms");
    }
    if (current.security().federation.pending_join_max_pdus != next.security().federation.pending_join_max_pdus)
    {
        add_change(plan, "security.federation.pending_join_max_pdus");
    }
    if (current.server().push.max_pushers_per_delivery != next.server().push.max_pushers_per_delivery)
    {
        add_change(plan, "server.push.max_pushers_per_delivery");
    }
    if (current.server().push.max_in_flight_deliveries != next.server().push.max_in_flight_deliveries)
    {
        add_change(plan, "server.push.max_in_flight_deliveries");
    }
    if (current.server().client_api.max_body_size != next.server().client_api.max_body_size)
    {
        add_change(plan, "server.client_api.max_body_size");
    }
    if (current.server().http.max_body_size != next.server().http.max_body_size)
    {
        add_change(plan, "server.http.max_body_size");
    }
    if (current.security().federation.backfill.response_max_size !=
        next.security().federation.backfill.response_max_size)
    {
        add_change(plan, "security.federation.backfill.response_max_size");
    }
    if (current.security().federation.pending_join_max_size != next.security().federation.pending_join_max_size)
    {
        add_change(plan, "security.federation.pending_join_max_size");
    }
    if (current.security().federation.bad_signature_per_ip_rate.max_requests !=
            next.security().federation.bad_signature_per_ip_rate.max_requests ||
        current.security().federation.bad_signature_per_ip_rate.window_seconds !=
            next.security().federation.bad_signature_per_ip_rate.window_seconds)
    {
        add_change(plan, "security.federation.bad_signature_per_ip_rate");
    }

    if (current.security().federation.backfill.max_total_outbound_calls !=
        next.security().federation.backfill.max_total_outbound_calls)
    {
        add_change(plan, "security.federation.backfill.max_total_outbound_calls");
    }
    if (current.security().federation.backfill.timeout != next.security().federation.backfill.timeout)
    {
        add_change(plan, "security.federation.backfill.timeout");
    }
    if (current.server().client_api.max_registration_validation_sessions !=
        next.server().client_api.max_registration_validation_sessions)
    {
        add_change(plan, "server.client_api.max_registration_validation_sessions");
    }
    if (current.server().client_api.max_registration_validation_sessions_per_remote !=
        next.server().client_api.max_registration_validation_sessions_per_remote)
    {
        add_change(plan, "server.client_api.max_registration_validation_sessions_per_remote");
    }
    if (current.server().client_api.max_uia_sessions != next.server().client_api.max_uia_sessions)
    {
        add_change(plan, "server.client_api.max_uia_sessions");
    }
    if (current.server().client_api.max_safety_report_rows != next.server().client_api.max_safety_report_rows)
    {
        add_change(plan, "server.client_api.max_safety_report_rows");
    }
    if (current.server().client_api.max_notifications_page_size != next.server().client_api.max_notifications_page_size)
    {
        add_change(plan, "server.client_api.max_notifications_page_size");
    }
    if (current.security().federation.query.max_backfill_pdus != next.security().federation.query.max_backfill_pdus)
    {
        add_change(plan, "security.federation.query.max_backfill_pdus");
    }
    if (current.security().federation.query.max_missing_events_pdus !=
        next.security().federation.query.max_missing_events_pdus)
    {
        add_change(plan, "security.federation.query.max_missing_events_pdus");
    }
    if (current.security().federation.query.max_missing_events_latest !=
        next.security().federation.query.max_missing_events_latest)
    {
        add_change(plan, "security.federation.query.max_missing_events_latest");
    }
    if (current.security().federation.query.max_missing_events_traversal !=
        next.security().federation.query.max_missing_events_traversal)
    {
        add_change(plan, "security.federation.query.max_missing_events_traversal");
    }
    if (current.security().federation.state_resolution.max_state_groups !=
        next.security().federation.state_resolution.max_state_groups)
    {
        add_change(plan, "security.federation.state_resolution.max_state_groups");
    }
    if (current.security().federation.state_resolution.max_events_per_state_group !=
        next.security().federation.state_resolution.max_events_per_state_group)
    {
        add_change(plan, "security.federation.state_resolution.max_events_per_state_group");
    }
    if (current.security().federation.state_resolution.max_total_state_events !=
        next.security().federation.state_resolution.max_total_state_events)
    {
        add_change(plan, "security.federation.state_resolution.max_total_state_events");
    }
    if (current.security().federation.state_resolution.max_conflicted_state_keys !=
        next.security().federation.state_resolution.max_conflicted_state_keys)
    {
        add_change(plan, "security.federation.state_resolution.max_conflicted_state_keys");
    }
    if (current.security().federation.state_resolution.max_mainline_auth_chain_depth !=
        next.security().federation.state_resolution.max_mainline_auth_chain_depth)
    {
        add_change(plan, "security.federation.state_resolution.max_mainline_auth_chain_depth");
    }
    if (current.security().federation.state_resolution.max_auth_chain_walk_events !=
        next.security().federation.state_resolution.max_auth_chain_walk_events)
    {
        add_change(plan, "security.federation.state_resolution.max_auth_chain_walk_events");
    }
    if (current.server().client_api.max_notifications_retained_per_user !=
        next.server().client_api.max_notifications_retained_per_user)
    {
        add_change(plan, "server.client_api.max_notifications_retained_per_user");
    }
    if (current.server().client_api.max_one_time_keys_per_device !=
        next.server().client_api.max_one_time_keys_per_device)
    {
        add_change(plan, "server.client_api.max_one_time_keys_per_device");
    }
    if (current.server().client_api.max_key_signatures_per_user != next.server().client_api.max_key_signatures_per_user)
    {
        add_change(plan, "server.client_api.max_key_signatures_per_user");
    }
    if (current.server().client_api.max_filters_per_user != next.server().client_api.max_filters_per_user)
    {
        add_change(plan, "server.client_api.max_filters_per_user");
    }
    if (current.server().client_api.max_threads_page_size != next.server().client_api.max_threads_page_size)
    {
        add_change(plan, "server.client_api.max_threads_page_size");
    }
    if (current.server().client_api.max_relations_page_size != next.server().client_api.max_relations_page_size)
    {
        add_change(plan, "server.client_api.max_relations_page_size");
    }
    if (current.server().client_api.max_public_rooms_page_size != next.server().client_api.max_public_rooms_page_size)
    {
        add_change(plan, "server.client_api.max_public_rooms_page_size");
    }
    if (current.server().client_api.max_hierarchy_rooms != next.server().client_api.max_hierarchy_rooms)
    {
        add_change(plan, "server.client_api.max_hierarchy_rooms");
    }
    if (current.security().federation.outbound_queue_capacity != next.security().federation.outbound_queue_capacity)
    {
        add_change(plan, "security.federation.outbound_queue_capacity");
    }
    if (current.security().federation.outbound_max_retries != next.security().federation.outbound_max_retries)
    {
        add_change(plan, "security.federation.outbound_max_retries");
    }
    if (current.appservice().connect_timeout_seconds != next.appservice().connect_timeout_seconds)
    {
        add_change(plan, "appservice.connect_timeout_seconds");
    }
    if (current.appservice().total_timeout_seconds != next.appservice().total_timeout_seconds)
    {
        add_change(plan, "appservice.total_timeout_seconds");
    }
    if (current.appservice().response_max_size != next.appservice().response_max_size)
    {
        add_change(plan, "appservice.response_max_size");
    }
    return plan;
}

auto reload_plan_summary(ReloadPlan const& plan) -> std::string
{
    return "Reload plan: changes=" + std::to_string(plan.changes().size()) +
           " reloadable=" + std::to_string(plan.reloadable_change_count()) +
           " restart_required=" + std::to_string(plan.restart_required_change_count());
}

} // namespace merovingian::config
