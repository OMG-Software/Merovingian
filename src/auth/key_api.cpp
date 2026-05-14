// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/key_api.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::auth
{
namespace
{

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto key_api_rate_limit() noexcept -> http::RateLimitPolicy
    {
        return {30U, 60U};
    }

    [[nodiscard]] auto route(std::string method, std::string path_template, KeyApiEndpoint endpoint) -> KeyApiRoute
    {
        return {std::move(method), std::move(path_template), endpoint, true, true, key_api_rate_limit()};
    }

    [[nodiscard]] auto public_value(std::string_view value) -> database::BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto sensitive_placeholder(std::string_view value) -> database::BoundValue
    {
        return {std::string{value}, true};
    }

    [[nodiscard]] auto user_device_params(std::string_view user_id, std::string_view device_id)
        -> std::vector<database::BoundValue>
    {
        return {public_value(user_id), public_value(device_id)};
    }

} // namespace

auto key_api_endpoint_name(KeyApiEndpoint endpoint) noexcept -> char const*
{
    switch (endpoint)
    {
    case KeyApiEndpoint::upload_keys:
        return "upload_keys";
    case KeyApiEndpoint::query_keys:
        return "query_keys";
    case KeyApiEndpoint::claim_keys:
        return "claim_keys";
    case KeyApiEndpoint::device_list_update:
        return "device_list_update";
    case KeyApiEndpoint::upload_cross_signing_keys:
        return "upload_cross_signing_keys";
    case KeyApiEndpoint::upload_signatures:
        return "upload_signatures";
    case KeyApiEndpoint::get_key_backup_version:
        return "get_key_backup_version";
    case KeyApiEndpoint::create_key_backup_version:
        return "create_key_backup_version";
    case KeyApiEndpoint::update_key_backup_version:
        return "update_key_backup_version";
    case KeyApiEndpoint::delete_key_backup_version:
        return "delete_key_backup_version";
    case KeyApiEndpoint::put_room_key_backup:
        return "put_room_key_backup";
    case KeyApiEndpoint::get_room_key_backup:
        return "get_room_key_backup";
    case KeyApiEndpoint::delete_room_key_backup:
        return "delete_room_key_backup";
    }

    return "unknown";
}

auto key_api_routes() -> std::vector<KeyApiRoute>
{
    return {
        route("POST", "/_matrix/client/v3/keys/upload", KeyApiEndpoint::upload_keys),
        route("POST", "/_matrix/client/v3/keys/query", KeyApiEndpoint::query_keys),
        route("POST", "/_matrix/client/v3/keys/claim", KeyApiEndpoint::claim_keys),
        route("POST", "/_matrix/client/v3/keys/device_signing/upload", KeyApiEndpoint::upload_cross_signing_keys),
        route("POST", "/_matrix/client/v3/keys/signatures/upload", KeyApiEndpoint::upload_signatures),
        route("GET", "/_matrix/client/v3/room_keys/version", KeyApiEndpoint::get_key_backup_version),
        route("POST", "/_matrix/client/v3/room_keys/version", KeyApiEndpoint::create_key_backup_version),
        route("PUT", "/_matrix/client/v3/room_keys/version/{version}", KeyApiEndpoint::update_key_backup_version),
        route("DELETE", "/_matrix/client/v3/room_keys/version/{version}", KeyApiEndpoint::delete_key_backup_version),
        route("PUT", "/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}", KeyApiEndpoint::put_room_key_backup),
        route("GET", "/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}", KeyApiEndpoint::get_room_key_backup),
        route("DELETE", "/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}",
              KeyApiEndpoint::delete_room_key_backup),
        route("PUT", "/_matrix/client/v3/devices/{deviceId}", KeyApiEndpoint::device_list_update),
    };
}

auto match_key_api_route(std::string_view method, std::string_view target) -> KeyApiRouteMatch
{
    for (auto const& candidate : key_api_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target)
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/room_keys/version/{version}" &&
            starts_with(target, "/_matrix/client/v3/room_keys/version/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}" &&
            starts_with(target, "/_matrix/client/v3/room_keys/keys/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/devices/{deviceId}" &&
            starts_with(target, "/_matrix/client/v3/devices/"))
        {
            return {true, candidate, {}};
        }
    }

    return {false, {}, "key API route not found"};
}

auto key_api_database_statements(KeyApiEndpoint endpoint, std::string_view user_id, std::string_view device_id)
    -> std::vector<database::PreparedStatement>
{
    switch (endpoint)
    {
    case KeyApiEndpoint::upload_keys:
        return {
            {"key_api_store_one_time_keys",
             "INSERT INTO one_time_keys VALUES ($1, $2, $3, $4)", {public_value(user_id), public_value(device_id), public_value("key_id"),
              sensitive_placeholder("one-time-key-payload")}},
            {"key_api_store_fallback_keys",
             "INSERT INTO fallback_keys VALUES ($1, $2, $3, $4)", {public_value(user_id), public_value(device_id), public_value("key_id"),
              sensitive_placeholder("fallback-key-payload")}},
        };
    case KeyApiEndpoint::query_keys:
        return {
            {"key_api_query_device_keys", "SELECT json FROM device_keys WHERE user_id = $1", {public_value(user_id)}}
        };
    case KeyApiEndpoint::claim_keys:
        return {
            {"key_api_claim_one_time_keys", "DELETE FROM one_time_keys WHERE user_id = $1 AND device_id = $2",
             user_device_params(user_id, device_id)}
        };
    case KeyApiEndpoint::device_list_update:
        return {
            {"key_api_record_device_list_update", "INSERT INTO device_list_updates user_id, device_id VALUES $1, $2",
             user_device_params(user_id, device_id)}
        };
    case KeyApiEndpoint::upload_cross_signing_keys:
        return {
            {"key_api_store_cross_signing_keys",
             "INSERT INTO cross_signing_keys VALUES ($1, $2, $3)", {public_value(user_id), public_value("master"), sensitive_placeholder("cross-signing-key-payload")}}
        };
    case KeyApiEndpoint::upload_signatures:
        return {
            {"key_api_store_key_signatures",
             "INSERT INTO key_signatures VALUES ($1, $2, $3, $4)", {public_value(user_id), public_value(user_id), public_value(device_id),
              sensitive_placeholder("signature-payload")}}
        };
    case KeyApiEndpoint::get_key_backup_version:
        return {
            {"key_api_get_backup_version",
             "SELECT version, json FROM key_backup_versions WHERE user_id = $1", {public_value(user_id)}}
        };
    case KeyApiEndpoint::create_key_backup_version:
        return {
            {"key_api_create_backup_version",
             "INSERT INTO key_backup_versions VALUES ($1, $2, $3)", {public_value(user_id), public_value("1"), sensitive_placeholder("backup-version-metadata")}}
        };
    case KeyApiEndpoint::update_key_backup_version:
        return {
            {"key_api_update_backup_version",
             "UPDATE key_backup_versions SET json = $1 WHERE user_id = $2", {sensitive_placeholder("backup-version-metadata"), public_value(user_id)}}
        };
    case KeyApiEndpoint::delete_key_backup_version:
        return {
            {"key_api_delete_backup_version",
             "DELETE FROM key_backup_versions WHERE user_id = $1", {public_value(user_id)}}
        };
    case KeyApiEndpoint::put_room_key_backup:
        return {
            {"key_api_put_room_key_backup",
             "INSERT INTO key_backup_sessions VALUES ($1, $2, $3, $4, $5)", {public_value(user_id), public_value("1"), public_value("room_id"), public_value("session_id"),
              sensitive_placeholder("room-key-backup-payload")}}
        };
    case KeyApiEndpoint::get_room_key_backup:
        return {
            {"key_api_get_room_key_backup",
             "SELECT json FROM key_backup_sessions WHERE user_id = $1", {public_value(user_id)}}
        };
    case KeyApiEndpoint::delete_room_key_backup:
        return {
            {"key_api_delete_room_key_backup",
             "DELETE FROM key_backup_sessions WHERE user_id = $1", {public_value(user_id)}}
        };
    }

    return {};
}

auto make_key_api_boundary_plan(KeyApiRoute const& route, std::string_view user_id, std::string_view device_id)
    -> KeyApiBoundaryPlan
{
    return {
        route,
        key_api_database_statements(route.endpoint, user_id, device_id),
        std::string{"key_api."} + key_api_endpoint_name(route.endpoint),
    };
}

auto key_payload_is_loggable(std::string_view payload) noexcept -> bool
{
    return payload.empty();
}

auto redacted_key_payload_summary(std::string_view payload) -> std::string
{
    if (payload.empty())
    {
        return "[key-payload:empty]";
    }

    return "[key-payload:redacted:length=" + std::to_string(payload.size()) + ']';
}

} // namespace merovingian::auth
