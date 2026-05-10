// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/auth/client_server_api.hpp>

#include <string>
#include <vector>

namespace merovingian::auth
{
namespace
{

[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

[[nodiscard]] auto route(
    std::string method,
    std::string path_template,
    ClientAuthEndpoint endpoint
) -> ClientAuthRoute
{
    return {
        std::move(method),
        std::move(path_template),
        endpoint,
        client_auth_endpoint_requires_access_token(endpoint),
        true,
        http::endpoint_default_rate_limit(method, path_template),
    };
}

[[nodiscard]] auto sensitive(std::string_view value) -> database::BoundValue
{
    return {std::string{value}, true};
}

[[nodiscard]] auto public_value(std::string_view value) -> database::BoundValue
{
    return {std::string{value}, false};
}

[[nodiscard]] auto select_account_statement(std::string_view user_id) -> database::PreparedStatement
{
    return {
        "client_auth_select_account",
        "SELECT state, password_login_enabled FROM accounts WHERE user_id = $1",
        {public_value(user_id)},
    };
}

[[nodiscard]] auto select_device_statement(std::string_view user_id, std::string_view device_id) -> database::PreparedStatement
{
    return {
        "client_auth_select_device",
        "SELECT deleted FROM devices WHERE user_id = $1 AND device_id = $2",
        {public_value(user_id), public_value(device_id)},
    };
}

[[nodiscard]] auto insert_device_statement(std::string_view user_id, std::string_view device_id) -> database::PreparedStatement
{
    return {
        "client_auth_upsert_device",
        "INSERT INTO devices user_id, device_id VALUES $1, $2",
        {public_value(user_id), public_value(device_id)},
    };
}

[[nodiscard]] auto persist_token_hash_statement(
    std::string_view user_id,
    std::string_view device_id,
    TokenHash const& token_hash
) -> database::PreparedStatement
{
    return {
        "client_auth_persist_access_token_hash",
        "INSERT INTO access_tokens user_id, device_id, token_hash_algorithm, token_hash_value VALUES $1, $2, $3, $4",
        {public_value(user_id), public_value(device_id), public_value(token_hash.algorithm), sensitive(token_hash.value)},
    };
}

[[nodiscard]] auto revoke_device_token_statement(std::string_view user_id, std::string_view device_id) -> database::PreparedStatement
{
    return {
        "client_auth_revoke_device_tokens",
        "UPDATE access_tokens SET revoked = true WHERE user_id = $1 AND device_id = $2",
        {public_value(user_id), public_value(device_id)},
    };
}

[[nodiscard]] auto revoke_all_tokens_statement(std::string_view user_id) -> database::PreparedStatement
{
    return {
        "client_auth_revoke_all_tokens",
        "UPDATE access_tokens SET revoked = true WHERE user_id = $1",
        {public_value(user_id)},
    };
}

[[nodiscard]] auto list_devices_statement(std::string_view user_id) -> database::PreparedStatement
{
    return {
        "client_auth_list_devices",
        "SELECT device_id, display_name FROM devices WHERE user_id = $1",
        {public_value(user_id)},
    };
}

[[nodiscard]] auto update_device_statement(std::string_view user_id, std::string_view device_id) -> database::PreparedStatement
{
    return {
        "client_auth_update_device",
        "UPDATE devices SET display_name = $1 WHERE user_id = $2 AND device_id = $3",
        {public_value("display_name-bound-by-handler"), public_value(user_id), public_value(device_id)},
    };
}

[[nodiscard]] auto delete_device_statement(std::string_view user_id, std::string_view device_id) -> database::PreparedStatement
{
    return {
        "client_auth_delete_device",
        "UPDATE devices SET deleted = true WHERE user_id = $1 AND device_id = $2",
        {public_value(user_id), public_value(device_id)},
    };
}

} // namespace

auto client_auth_routes() -> std::vector<ClientAuthRoute>
{
    return {
        route("POST", "/_matrix/client/v3/login", ClientAuthEndpoint::login),
        route("POST", "/_matrix/client/v3/logout", ClientAuthEndpoint::logout),
        route("POST", "/_matrix/client/v3/logout/all", ClientAuthEndpoint::logout_all),
        route("POST", "/_matrix/client/v3/register", ClientAuthEndpoint::register_account),
        route("POST", "/_matrix/client/v3/refresh", ClientAuthEndpoint::refresh_token),
        route("GET", "/_matrix/client/v3/devices", ClientAuthEndpoint::list_devices),
        route("GET", "/_matrix/client/v3/devices/{deviceId}", ClientAuthEndpoint::get_device),
        route("PUT", "/_matrix/client/v3/devices/{deviceId}", ClientAuthEndpoint::update_device),
        route("DELETE", "/_matrix/client/v3/devices/{deviceId}", ClientAuthEndpoint::delete_device),
    };
}

auto match_client_auth_route(std::string_view method, std::string_view target) -> ClientAuthRouteMatch
{
    for (auto const& candidate : client_auth_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target)
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/devices/{deviceId}"
            && starts_with(target, "/_matrix/client/v3/devices/"))
        {
            return {true, candidate, {}};
        }
    }

    return {false, {}, "client auth route not found"};
}

auto client_auth_token_hashing_plan(ClientAuthEndpoint endpoint) -> ClientAuthTokenHashingPlan
{
    if (endpoint == ClientAuthEndpoint::login || endpoint == ClientAuthEndpoint::register_account
        || endpoint == ClientAuthEndpoint::refresh_token)
    {
        return {true, true, true, false, 32U, "external-kdf"};
    }

    return {false, false, false, false, 0U, {}};
}

auto client_auth_database_statements(
    ClientAuthEndpoint endpoint,
    std::string_view user_id,
    std::string_view device_id,
    TokenHash const& token_hash
) -> std::vector<database::PreparedStatement>
{
    switch (endpoint)
    {
    case ClientAuthEndpoint::login:
        return {select_account_statement(user_id), insert_device_statement(user_id, device_id), persist_token_hash_statement(user_id, device_id, token_hash)};
    case ClientAuthEndpoint::logout:
        return {select_device_statement(user_id, device_id), revoke_device_token_statement(user_id, device_id)};
    case ClientAuthEndpoint::logout_all:
        return {revoke_all_tokens_statement(user_id)};
    case ClientAuthEndpoint::register_account:
        return {insert_device_statement(user_id, device_id), persist_token_hash_statement(user_id, device_id, token_hash)};
    case ClientAuthEndpoint::refresh_token:
        return {select_device_statement(user_id, device_id), persist_token_hash_statement(user_id, device_id, token_hash)};
    case ClientAuthEndpoint::list_devices:
        return {list_devices_statement(user_id)};
    case ClientAuthEndpoint::get_device:
        return {select_device_statement(user_id, device_id)};
    case ClientAuthEndpoint::update_device:
        return {select_device_statement(user_id, device_id), update_device_statement(user_id, device_id)};
    case ClientAuthEndpoint::delete_device:
        return {select_device_statement(user_id, device_id), delete_device_statement(user_id, device_id), revoke_device_token_statement(user_id, device_id)};
    }

    return {};
}

auto make_client_auth_boundary_plan(
    ClientAuthRoute const& route,
    std::string_view user_id,
    std::string_view device_id,
    TokenHash const& token_hash,
    bool allowed,
    std::string_view reason
) -> ClientAuthBoundaryPlan
{
    return {
        route,
        client_auth_database_statements(route.endpoint, user_id, device_id, token_hash),
        client_auth_token_hashing_plan(route.endpoint),
        make_client_auth_audit_event(route.endpoint, user_id, device_id, allowed, reason),
    };
}

} // namespace merovingian::auth
