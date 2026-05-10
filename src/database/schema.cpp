// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/schema.hpp>

#include <algorithm>
#include <array>

namespace merovingian::database
{
namespace
{

constexpr auto core_tables = std::array{
    std::string_view{"users"},
    std::string_view{"devices"},
    std::string_view{"access_tokens"},
    std::string_view{"refresh_tokens"},
    std::string_view{"server_signing_keys"},
    std::string_view{"rooms"},
    std::string_view{"room_versions"},
    std::string_view{"events"},
    std::string_view{"event_json"},
    std::string_view{"event_edges"},
    std::string_view{"event_auth"},
    std::string_view{"event_signatures"},
    std::string_view{"current_state"},
    std::string_view{"state_groups"},
    std::string_view{"state_group_edges"},
    std::string_view{"membership"},
    std::string_view{"invites"},
    std::string_view{"account_data"},
    std::string_view{"push_rules"},
    std::string_view{"filters"},
    std::string_view{"one_time_keys"},
    std::string_view{"fallback_keys"},
    std::string_view{"cross_signing_keys"},
    std::string_view{"key_backups"},
    std::string_view{"media"},
    std::string_view{"remote_media"},
    std::string_view{"federation_destinations"},
    std::string_view{"federation_transactions"},
    std::string_view{"rate_limits"},
    std::string_view{"audit_log"},
    std::string_view{"policy_rules"},
    std::string_view{"admin_actions"},
};

} // namespace

auto initial_schema_tables() -> std::vector<std::string_view>
{
    return {core_tables.begin(), core_tables.end()};
}

auto schema_table_is_core(std::string_view table_name) noexcept -> bool
{
    return std::ranges::find(core_tables, table_name) != core_tables.end();
}

} // namespace merovingian::database
