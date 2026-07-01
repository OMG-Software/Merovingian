// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/reload_plan.hpp"

#include <string>
#include <utility>

namespace merovingian::config
{
namespace
{

    auto add_change(ReloadPlan& plan, std::string const& key) -> void
    {
        plan.add_change({key, reload_policy_for_key(key)});
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

    if (current.listeners().client.bind != next.listeners().client.bind)
    {
        add_change(plan, "listeners.client.bind");
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

    return plan;
}

auto reload_plan_summary(ReloadPlan const& plan) -> std::string
{
    return "Reload plan: changes=" + std::to_string(plan.changes().size()) +
           " reloadable=" + std::to_string(plan.reloadable_change_count()) +
           " restart_required=" + std::to_string(plan.restart_required_change_count());
}

} // namespace merovingian::config
