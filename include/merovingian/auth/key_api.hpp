// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/statement.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::auth
{

enum class KeyApiEndpoint
{
    upload_keys,
    query_keys,
    claim_keys,
    device_list_update,
    upload_cross_signing_keys,
    upload_signatures,
    get_key_backup_version,
    create_key_backup_version,
    update_key_backup_version,
    delete_key_backup_version,
    put_room_key_backup,
    get_room_key_backup,
    delete_room_key_backup,
};

struct KeyApiRoute final
{
    std::string method{};
    std::string path_template{};
    KeyApiEndpoint endpoint{KeyApiEndpoint::upload_keys};
    bool requires_access_token{true};
    bool stores_server_blind_payload{true};
    http::RateLimitPolicy rate_limit{};
};

struct KeyApiRouteMatch final
{
    bool matched{false};
    KeyApiRoute route{};
    std::string reason{};
};

struct KeyApiBoundaryPlan final
{
    KeyApiRoute route{};
    std::vector<database::PreparedStatement> database_statements{};
    std::string audit_event_type{};
};

[[nodiscard]] auto key_api_endpoint_name(KeyApiEndpoint endpoint) noexcept -> char const*;
[[nodiscard]] auto key_api_routes() -> std::vector<KeyApiRoute>;
[[nodiscard]] auto match_key_api_route(std::string_view method, std::string_view target) -> KeyApiRouteMatch;
[[nodiscard]] auto key_api_database_statements(KeyApiEndpoint endpoint, std::string_view user_id,
                                               std::string_view device_id) -> std::vector<database::PreparedStatement>;
[[nodiscard]] auto make_key_api_boundary_plan(KeyApiRoute const& route, std::string_view user_id,
                                              std::string_view device_id) -> KeyApiBoundaryPlan;
[[nodiscard]] auto key_payload_is_loggable(std::string_view payload) noexcept -> bool;
[[nodiscard]] auto redacted_key_payload_summary(std::string_view payload) -> std::string;

} // namespace merovingian::auth
