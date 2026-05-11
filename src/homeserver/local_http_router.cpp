// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

[[nodiscard]] auto response(std::uint16_t status, std::string body) -> LocalHttpResponse
{
    return {status, std::move(body)};
}

[[nodiscard]] auto response_from_operation(OperationResult const& result, std::uint16_t ok_status = 200U) -> LocalHttpResponse
{
    return result.ok ? response(ok_status, result.value) : response(400U, result.reason);
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
    if (first == std::string_view::npos || first == 0U || second == std::string_view::npos || second == first + 1U || second + 1U >= body.size())
    {
        return std::nullopt;
    }
    return std::array<std::string_view, 3U>{body.substr(0U, first), body.substr(first + 1U, second - first - 1U), body.substr(second + 1U)};
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
        result = (result * 10U) + static_cast<std::uint64_t>(character - '0');
    }
    return result;
}

[[nodiscard]] auto parse_signed_federation_request(LocalHttpRequest const& request) -> std::optional<federation::SignedFederationRequest>
{
    auto const fields = split_pipe_6(request.access_token);
    if (!fields.has_value())
    {
        return std::nullopt;
    }
    auto const origin_ts = parse_u64((*fields)[3]);
    auto const now_ts = parse_u64((*fields)[4]);
    if (!origin_ts.has_value() || !now_ts.has_value())
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
        *now_ts,
        request.body,
    };
}

} // namespace

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (!runtime.started)
    {
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/health")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value() ? response(200U, admin_health_summary(runtime))
                                                                 : response(401U, "admin authentication required");
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        auto signed_request = parse_signed_federation_request(request);
        if (!signed_request.has_value())
        {
            return response(401U, "malformed federation authorization");
        }
        auto const federation_response = federation::handle_inbound_federation_request(runtime.federation, *signed_request);
        return response(federation_response.status, federation_response.body);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/register")
    {
        auto const fields = split_pipe_2(request.body);
        return fields.has_value() ? response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1]), 200U)
                                  : response(400U, "registration body must be localpart|password");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/login")
    {
        auto const fields = split_pipe_3(request.body);
        return fields.has_value() ? response_from_operation(login_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]), 200U)
                                  : response(400U, "login body must be user_id|password|device_id");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/logout")
    {
        auto result = logout_local_user(runtime, request.access_token);
        return result.ok ? response(200U, "logged out") : response(401U, result.reason);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/createRoom")
    {
        auto result = create_room(runtime, request.access_token);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }

    auto constexpr rooms_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (!starts_with(request.target, rooms_prefix))
    {
        return response(404U, "route not found");
    }
    auto const suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size() && suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto result = join_room(runtime, request.access_token, suffix.substr(0U, suffix.size() - join_suffix.size()));
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }
    if (request.method == "POST" && suffix.size() > send_suffix.size() && suffix.substr(suffix.size() - send_suffix.size()) == send_suffix)
    {
        auto result = send_event(runtime, request.access_token, suffix.substr(0U, suffix.size() - send_suffix.size()), request.body);
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }
    if (request.method == "GET" && suffix.size() > state_suffix.size() && suffix.substr(suffix.size() - state_suffix.size()) == state_suffix)
    {
        auto result = fetch_room_state(runtime, request.access_token, suffix.substr(0U, suffix.size() - state_suffix.size()));
        return result.ok ? response(200U, result.value) : response(401U, result.reason);
    }
    return response(404U, "route not found");
}

} // namespace merovingian::homeserver
