// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/worker_relay_binding.hpp"

#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/generic_hash.hpp"
#include "merovingian/federation/FederationEndpoint.hpp"
#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/federation/transactions.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::federation
{

namespace
{

    [[nodiscard]] constexpr auto relay_kind_name(WorkerRelayKind kind) noexcept -> std::string_view
    {
        switch (kind)
        {
        case WorkerRelayKind::otk_claim:
            return "otk_claim";
        case WorkerRelayKind::device_keys_query:
            return "device_keys_query";
        case WorkerRelayKind::user_devices:
            return "user_devices";
        case WorkerRelayKind::profile_query:
            return "profile_query";
        }
        return "unknown";
    }

    auto constexpr user_devices_prefix = std::string_view{"/_matrix/federation/v1/user/devices/"};

    // Appends the digest of (kind, argument) to `digests`; false when the hash fails.
    [[nodiscard]] auto append_digest(std::vector<std::string>& digests, WorkerRelayKind kind, std::string_view argument)
        -> bool
    {
        auto digest = worker_relay_digest(kind, argument);
        if (!digest.has_value())
        {
            return false;
        }
        digests.push_back(std::move(*digest));
        return true;
    }

} // namespace

auto request_query_parameter(std::string_view target, std::string_view name) -> std::string
{
    auto const query_start = target.find('?');
    if (query_start == std::string_view::npos)
    {
        return {};
    }
    auto remaining = target.substr(query_start + 1U);
    while (!remaining.empty())
    {
        auto const amp = remaining.find('&');
        auto const pair = remaining.substr(0U, amp);
        auto const eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0U, eq) == name)
        {
            return core::percent_decode(pair.substr(eq + 1U));
        }
        if (amp == std::string_view::npos)
        {
            break;
        }
        remaining = remaining.substr(amp + 1U);
    }
    return {};
}

auto user_devices_path_user_id(std::string_view target) -> std::optional<std::string>
{
    auto const path = target.substr(0U, target.find('?'));
    if (path.size() <= user_devices_prefix.size() || !path.starts_with(user_devices_prefix))
    {
        return std::nullopt;
    }
    return core::percent_decode(path.substr(user_devices_prefix.size()));
}

auto worker_relay_digest(WorkerRelayKind kind, std::string_view argument) -> std::optional<std::string>
{
    auto const name = relay_kind_name(kind);
    auto const argument_length = std::to_string(argument.size());
    auto const pieces = std::array<std::string_view, 6U>{"relay:", name, ":", argument_length, ":", argument};
    return crypto::generic_hash(pieces);
}

auto verified_request_relay_digests(std::string_view method, std::string_view target, std::string_view body)
    -> std::vector<std::string>
{
    auto digests = std::vector<std::string>{};
    auto const route = match_federation_route(method, target);
    if (!route.matched)
    {
        return digests;
    }
    switch (route.route.endpoint)
    {
    case FederationEndpoint::claim_keys:
        std::ignore = append_digest(digests, WorkerRelayKind::otk_claim, body);
        break;
    case FederationEndpoint::query_keys:
        std::ignore = append_digest(digests, WorkerRelayKind::device_keys_query, body);
        break;
    case FederationEndpoint::query_user_devices:
        if (auto const user_id = user_devices_path_user_id(target); user_id.has_value())
        {
            std::ignore = append_digest(digests, WorkerRelayKind::user_devices, *user_id);
        }
        break;
    case FederationEndpoint::query_profile:
        if (auto const user_id = request_query_parameter(target, "user_id"); !user_id.empty())
        {
            std::ignore = append_digest(digests, WorkerRelayKind::profile_query, user_id);
        }
        break;
    default:
        break;
    }
    return digests;
}

} // namespace merovingian::federation
