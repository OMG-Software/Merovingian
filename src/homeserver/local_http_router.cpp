// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("local_router", event, std::move(fields)));
    }

    [[nodiscard]] auto response(std::uint16_t status, std::string body) -> LocalHttpResponse
    {
        return {status, std::move(body)};
    }

    [[nodiscard]] auto response_from_operation(OperationResult const& result, std::uint16_t ok_status = 200U)
        -> LocalHttpResponse
    {
        return result.ok ? response(ok_status, result.value) : response(result.status, result.reason);
    }

    [[nodiscard]] auto response_from_media_operation(OperationResult const& result) -> LocalHttpResponse
    {
        return response(result.status, result.ok ? result.value : result.reason);
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto split_pipe_2(std::string_view body) -> std::optional<std::array<std::string_view, 2U>>
    {
        auto const first = body.find('|');
        if (first == std::string_view::npos || first == 0U || first + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{body.substr(0U, first), body.substr(first + 1U)};
    }

    [[nodiscard]] auto split_pipe_3(std::string_view body) -> std::optional<std::array<std::string_view, 3U>>
    {
        auto const first = body.find('|');
        auto const second = first == std::string_view::npos ? std::string_view::npos : body.find('|', first + 1U);
        if (first == std::string_view::npos || first == 0U || second == std::string_view::npos ||
            second == first + 1U || second + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 3U>{body.substr(0U, first), body.substr(first + 1U, second - first - 1U),
                                                body.substr(second + 1U)};
    }

    [[nodiscard]] auto split_pipe_4(std::string_view body) -> std::optional<std::array<std::string_view, 4U>>
    {
        auto fields = std::array<std::string_view, 4U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            auto const separator = remaining.find('|');
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto split_pipe_6(std::string_view body) -> std::optional<std::array<std::string_view, 6U>>
    {
        auto fields = std::array<std::string_view, 6U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            auto const separator = remaining.find('|');
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto parse_u64(std::string_view value) noexcept -> std::optional<std::uint64_t>
    {
        if (value.empty())
        {
            return std::nullopt;
        }
        auto result = std::uint64_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(character - '0');
            if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return std::nullopt;
            }
            result = (result * 10U) + digit;
        }
        return result;
    }

    [[nodiscard]] auto parse_bool_flag(std::string_view value) noexcept -> std::optional<bool>
    {
        if (value == "canonical" || value == "true" || value == "clean")
        {
            return true;
        }
        if (value == "uncanonical" || value == "false" || value == "dirty")
        {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto parse_signed_federation_request(LocalHttpRequest const& request)
        -> std::optional<federation::SignedFederationRequest>
    {
        auto const fields = split_pipe_6(request.access_token);
        if (!fields.has_value())
        {
            return std::nullopt;
        }
        auto const origin_ts = parse_u64((*fields)[3]);
        auto const received_ts = parse_u64((*fields)[4]);
        auto const canonical_json_verified = parse_bool_flag((*fields)[5]);
        if (!origin_ts.has_value() || !received_ts.has_value() || !canonical_json_verified.has_value())
        {
            return std::nullopt;
        }
        return federation::SignedFederationRequest{
            request.method,
            request.target,
            std::string{(*fields)[0]},
            std::string{(*fields)[1]},
            std::string{(*fields)[2]},
            *origin_ts,
            *received_ts,
            *canonical_json_verified,
            request.body,
        };
    }

    [[nodiscard]] auto path_suffix(std::string_view target, std::string_view prefix) noexcept -> std::string_view
    {
        return starts_with(target, prefix) ? target.substr(prefix.size()) : std::string_view{};
    }

    [[nodiscard]] auto local_media_download_parts(std::string_view suffix)
        -> std::optional<std::array<std::string_view, 2U>>
    {
        auto const separator = suffix.find('/');
        if (separator == std::string_view::npos || separator == 0U || separator + 1U >= suffix.size())
        {
            return std::nullopt;
        }
        auto const server_name = suffix.substr(0U, separator);
        auto const media_id = suffix.substr(separator + 1U);
        if (media_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{server_name, media_id};
    }

} // namespace

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    log_diagnostic("request.received",
                   {
                       {"method",           request.method,                                       false},
                       {"target",           observability::sanitized_http_target(request.target), false},
                       {"body_bytes",       std::to_string(request.body.size()),                  false},
                       {"has_access_token", request.access_token.empty() ? "false" : "true",      false}
    });
    if (!runtime.started)
    {
        log_diagnostic("request.rejected", {
                                               {"method", request.method,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "503",                                                false},
                                               {"reason", "runtime not started",                                false}
        });
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/health")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_health_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/media/metrics")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, media_metrics_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/metrics")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_metrics_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/audit")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_audit_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_matrix/key/v2/server")
    {
        return response_from_operation(publish_server_signing_keys(runtime));
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        auto signed_request = parse_signed_federation_request(request);
        if (!signed_request.has_value())
        {
            log_diagnostic("federation.auth.rejected",
                           {
                               {"method", request.method,                                       false},
                               {"target", observability::sanitized_http_target(request.target), false},
                               {"status", "401",                                                false},
                               {"reason", "malformed federation authorization",                 false}
            });
            return response(401U, "malformed federation authorization");
        }
        auto const federation_response =
            federation::handle_inbound_federation_request(runtime.federation, *signed_request);
        log_diagnostic("federation.dispatched",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"origin", signed_request->origin,                               false},
                           {"status", std::to_string(federation_response.status),           false}
        });
        return response(federation_response.status, federation_response.body);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/register")
    {
        if (auto const fields = split_pipe_3(request.body); fields.has_value())
        {
            return response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]),
                                           200U);
        }
        auto const fields = split_pipe_2(request.body);
        return fields.has_value()
                   ? response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1]), 200U)
                   : response(400U, "registration body must be localpart|password[|token]");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/login")
    {
        auto const fields = split_pipe_3(request.body);
        return fields.has_value()
                   ? response_from_operation(login_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]), 200U)
                   : response(400U, "login body must be user_id|password|device_id");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/logout")
    {
        auto result = logout_local_user(runtime, request.access_token);
        return result.ok ? response(200U, "logged out") : response(401U, result.reason);
    }
    if (request.method == "POST" && request.target == "/_matrix/media/v3/upload")
    {
        auto const fields = split_pipe_4(request.body);
        if (!fields.has_value())
        {
            return response(400U, "upload body must be declared_mime|sniffed_mime|scanner_clean|bytes");
        }
        auto const scanner_clean = parse_bool_flag((*fields)[2]);
        if (!scanner_clean.has_value())
        {
            return response(400U, "scanner_clean must be clean or dirty");
        }
        auto const result =
            upload_local_media(runtime, request.access_token, (*fields)[0], (*fields)[1], *scanner_clean, (*fields)[3]);
        return response_from_media_operation(result);
    }
    auto constexpr download_prefix = std::string_view{"/_matrix/media/v3/download/"};
    if (request.method == "GET" && starts_with(request.target, download_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, download_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result = download_local_media(runtime, (*parts)[0], (*parts)[1]);
        return response_from_media_operation(result);
    }
    auto constexpr quarantine_prefix = std::string_view{"/_merovingian/admin/media/quarantine/"};
    if (request.method == "POST" && starts_with(request.target, quarantine_prefix))
    {
        auto const media_id = path_suffix(request.target, quarantine_prefix);
        auto const result = admin_quarantine_local_media(runtime, request.access_token, media_id, request.body);
        return response_from_media_operation(result);
    }
    auto constexpr release_prefix = std::string_view{"/_merovingian/admin/media/release/"};
    if (request.method == "POST" && starts_with(request.target, release_prefix))
    {
        auto const media_id = path_suffix(request.target, release_prefix);
        auto const result = admin_release_local_media(runtime, request.access_token, media_id);
        return response_from_media_operation(result);
    }
    auto constexpr remove_prefix = std::string_view{"/_merovingian/admin/media/remove/"};
    if (request.method == "POST" && starts_with(request.target, remove_prefix))
    {
        auto const media_id = path_suffix(request.target, remove_prefix);
        auto const result = admin_remove_local_media(runtime, request.access_token, media_id, request.body);
        return response_from_media_operation(result);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/createRoom")
    {
        auto result = create_room(runtime, request.access_token);
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }

    auto constexpr rooms_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (!starts_with(request.target, rooms_prefix))
    {
        log_diagnostic("request.route_not_found",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"status", "404",                                                false}
        });
        return response(404U, "route not found");
    }
    auto const suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size() &&
        suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto const room_id = suffix.substr(0U, suffix.size() - join_suffix.size());
        log_diagnostic("room.join.dispatch", {
                                                 {"room_id", std::string{room_id}, false}
        });
        auto result = join_room(runtime, request.access_token, room_id);
        log_diagnostic(result.ok ? "room.join.accepted" : "room.join.rejected",
                       {
                           {"room_id", std::string{room_id},                                       false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "POST" && suffix.size() > send_suffix.size() &&
        suffix.substr(suffix.size() - send_suffix.size()) == send_suffix)
    {
        auto const room_id = suffix.substr(0U, suffix.size() - send_suffix.size());
        log_diagnostic("room.event.dispatch", {
                                                  {"room_id",    std::string{room_id},                false},
                                                  {"body_bytes", std::to_string(request.body.size()), false}
        });
        auto result = send_event(runtime, request.access_token, room_id, request.body);
        log_diagnostic(result.ok ? "room.event.accepted" : "room.event.rejected",
                       {
                           {"room_id", std::string{room_id},                                       false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "GET" && suffix.size() > state_suffix.size() &&
        suffix.substr(suffix.size() - state_suffix.size()) == state_suffix)
    {
        auto result =
            fetch_room_state(runtime, request.access_token, suffix.substr(0U, suffix.size() - state_suffix.size()));
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    log_diagnostic("request.route_not_found",
                   {
                       {"method", request.method,                                       false},
                       {"target", observability::sanitized_http_target(request.target), false},
                       {"status", "404",                                                false}
    });
    return response(404U, "route not found");
}

[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    if (!runtime.started)
    {
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_matrix/key/v2/server")
    {
        return response_from_operation(publish_server_signing_keys(runtime));
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        auto signed_request = parse_signed_federation_request(request);
        if (!signed_request.has_value())
        {
            return response(401U, "malformed federation authorization");
        }
        auto const federation_response =
            federation::handle_inbound_federation_request(runtime.federation, *signed_request);
        return response(federation_response.status, federation_response.body);
    }
    return response(404U, "route not found");
}

} // namespace merovingian::homeserver
