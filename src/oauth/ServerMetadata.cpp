// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/ServerMetadata.hpp"

#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/oauth/OAuthPaths.hpp"

#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::oauth
{
namespace
{

    // RFC 8628's grant type URN for the device authorization grant.
    constexpr auto device_code_grant_type = std::string_view{"urn:ietf:params:oauth:grant-type:device_code"};

    [[nodiscard]] auto string_list(std::initializer_list<std::string_view> items) -> canonicaljson::Value
    {
        auto array = canonicaljson::Array{};
        array.reserve(items.size());
        for (auto const item : items)
        {
            array.emplace_back(std::string{item});
        }
        return canonicaljson::Value{std::move(array)};
    }

    void add(canonicaljson::Object& object, std::string key, canonicaljson::Value value)
    {
        object.push_back(canonicaljson::make_member(std::move(key), std::move(value)));
    }

} // namespace

auto server_metadata(OAuthBaseUrl const& base, ServerMetadataOptions const& options) -> canonicaljson::Value
{
    auto object = canonicaljson::Object{};
    add(object, "issuer", canonicaljson::Value{base.issuer()});
    add(object, "authorization_endpoint", canonicaljson::Value{base.url(authorize_path)});
    add(object, "token_endpoint", canonicaljson::Value{base.url(token_path)});
    add(object, "registration_endpoint", canonicaljson::Value{base.url(register_path)});
    add(object, "revocation_endpoint", canonicaljson::Value{base.url(revoke_path)});
    add(object, "response_types_supported", string_list({"code"}));
    add(object, "response_modes_supported", string_list({"query", "fragment"}));
    add(object, "code_challenge_methods_supported", string_list({"S256"}));
    if (options.device_grant_enabled)
    {
        add(object, "grant_types_supported",
            string_list({"authorization_code", "refresh_token", device_code_grant_type}));
        add(object, "device_authorization_endpoint", canonicaljson::Value{base.url(device_path)});
    }
    else
    {
        add(object, "grant_types_supported", string_list({"authorization_code", "refresh_token"}));
    }
    if (options.registration_enabled)
    {
        add(object, "prompt_values_supported", string_list({"create"}));
    }
    if (!options.account_management_actions.empty())
    {
        add(object, "account_management_uri", canonicaljson::Value{base.url(account_path)});
        auto actions = canonicaljson::Array{};
        actions.reserve(options.account_management_actions.size());
        for (auto const& action : options.account_management_actions)
        {
            actions.emplace_back(action);
        }
        add(object, "account_management_actions_supported", canonicaljson::Value{std::move(actions)});
    }
    return canonicaljson::Value{std::move(object)};
}

} // namespace merovingian::oauth
