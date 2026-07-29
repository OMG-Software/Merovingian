// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/oidc_discovery.hpp"

#include "merovingian/canonicaljson/value.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::auth
{
namespace
{

    [[nodiscard]] auto json_str(std::string_view value) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::string{value}};
    }

    [[nodiscard]] auto json_arr(std::vector<std::string_view> items) -> canonicaljson::Value
    {
        auto array = canonicaljson::Array{};
        array.reserve(items.size());
        for (auto const item : items)
        {
            array.emplace_back(json_str(item));
        }
        return canonicaljson::Value{std::move(array)};
    }

    [[nodiscard]] auto json_member(std::string key, canonicaljson::Value value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::move(key), std::move(value));
    }

} // namespace

auto make_auth_metadata(config::OidcConfig const& config) -> AuthMetadata
{
    if (!config.enabled)
    {
        return {};
    }

    auto fields = canonicaljson::Object{};

    // Required by RFC 8414 / Matrix v1.19.
    fields.emplace_back(json_member("issuer", json_str(config.issuer)));
    fields.emplace_back(json_member("authorization_endpoint", json_str(config.authorization_endpoint)));
    fields.emplace_back(json_member("token_endpoint", json_str(config.token_endpoint)));
    fields.emplace_back(json_member("registration_endpoint", json_str(config.registration_endpoint)));
    fields.emplace_back(json_member("revocation_endpoint", json_str(config.revocation_endpoint)));

    fields.emplace_back(json_member("response_types_supported", json_arr({"code"})));
    fields.emplace_back(json_member("response_modes_supported", json_arr({"query", "fragment"})));
    fields.emplace_back(json_member("code_challenge_methods_supported", json_arr({"S256"})));
    fields.emplace_back(json_member("grant_types_supported", json_arr({"authorization_code", "refresh_token"})));

    // Optional device-authorization grant endpoint (RFC 8628).
    if (!config.device_authorization_endpoint.empty())
    {
        fields.emplace_back(
            json_member("device_authorization_endpoint", json_str(config.device_authorization_endpoint)));
    }

    // Optional account management URI and supported actions (Matrix v1.19 extension).
    if (!config.account_management_uri.empty())
    {
        fields.emplace_back(json_member("account_management_uri", json_str(config.account_management_uri)));

        if (!config.account_management_actions_supported.empty())
        {
            auto actions = canonicaljson::Array{};
            actions.reserve(config.account_management_actions_supported.size());
            for (auto const& action : config.account_management_actions_supported)
            {
                actions.emplace_back(json_str(action));
            }
            fields.emplace_back(
                json_member("account_management_actions_supported", canonicaljson::Value{std::move(actions)}));
        }
    }

    return {true, std::move(fields)};
}

} // namespace merovingian::auth
