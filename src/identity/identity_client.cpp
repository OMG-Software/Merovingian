// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/identity/identity_client.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <string>
#include <string_view>

namespace merovingian::identity
{
namespace
{

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    // Serializes an Object to a canonical JSON string. The IS request bodies
    // contain only string members, so serialize_canonical cannot fail.
    [[nodiscard]] auto serialize_object(canonicaljson::Object object) -> std::string
    {
        auto const result = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        return result.output;
    }

    [[nodiscard]] auto make_str_member(std::string_view key, std::string_view value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{std::string{value}});
    }

} // namespace

auto parse_identity_server_url(std::string_view url) -> std::optional<IdentityServerUrl>
{
    constexpr auto scheme = std::string_view{"https://"};
    if (!starts_with(url, scheme))
    {
        return std::nullopt;
    }
    auto const authority_start = scheme.size();
    auto const slash = url.find('/', authority_start);
    auto const authority = slash == std::string_view::npos ? url.substr(authority_start)
                                                           : url.substr(authority_start, slash - authority_start);
    if (authority.empty())
    {
        return std::nullopt;
    }

    IdentityServerUrl out{};
    out.port = 443U;
    // Split host:port. Only a numeric port after the last colon is honoured;
    // IPv6 literals are not expected in operator config (the IS base URL is an
    // HTTPS origin), so a colon inside brackets is not special-cased.
    auto const colon = authority.rfind(':');
    if (colon != std::string_view::npos)
    {
        auto const port_str = authority.substr(colon + 1U);
        try
        {
            auto const parsed = std::stoul(std::string{port_str});
            if (parsed == 0U || parsed > 65535U)
            {
                return std::nullopt;
            }
            out.host = std::string{authority.substr(0U, colon)};
            out.port = static_cast<std::uint16_t>(parsed);
        }
        catch (...)
        {
            // Not a numeric port — treat the whole authority as a host.
            out.host = std::string{authority};
        }
    }
    else
    {
        out.host = std::string{authority};
    }
    if (out.host.empty())
    {
        return std::nullopt;
    }
    // Capture any path prefix after the authority (e.g. "https://is/x" -> "/x").
    if (slash != std::string_view::npos)
    {
        out.path = std::string{url.substr(slash)};
        // Trailing slashes on the base URL are collapsed so the api path appends
        // cleanly; a lone "/" collapses to empty (root), not "/".  Leading slash
        // is preserved for real path prefixes (e.g. "/v2").
        while (!out.path.empty() && out.path.back() == '/')
        {
            out.path.pop_back();
        }
    }
    return out;
}

auto build_store_invite_body(std::string_view medium, std::string_view address, std::string_view room_id,
                             std::string_view sender) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(make_str_member("medium", medium));
    obj.push_back(make_str_member("address", address));
    obj.push_back(make_str_member("room_id", room_id));
    obj.push_back(make_str_member("sender", sender));
    return serialize_object(std::move(obj));
}

auto build_lookup_body(std::string_view medium, std::string_view address) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(make_str_member("medium", medium));
    obj.push_back(make_str_member("address", address));
    return serialize_object(std::move(obj));
}

auto build_bind_body(std::string_view client_secret, std::string_view sid, std::string_view mxid) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(make_str_member("client_secret", client_secret));
    obj.push_back(make_str_member("sid", sid));
    obj.push_back(make_str_member("mxid", mxid));
    return serialize_object(std::move(obj));
}

auto build_unbind_body(std::string_view client_secret, std::string_view sid, std::string_view medium,
                       std::string_view address) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(make_str_member("client_secret", client_secret));
    obj.push_back(make_str_member("sid", sid));
    obj.push_back(make_str_member("medium", medium));
    obj.push_back(make_str_member("address", address));
    return serialize_object(std::move(obj));
}

auto build_request_token_body(std::string_view client_secret, std::string_view email, std::string_view next_link)
    -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(make_str_member("client_secret", client_secret));
    obj.push_back(make_str_member("email", email));
    if (!next_link.empty())
    {
        obj.push_back(make_str_member("next_link", next_link));
    }
    return serialize_object(std::move(obj));
}

auto parse_store_invite_response(std::string_view body) -> std::optional<StoreInviteResponse>
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return std::nullopt;
    }
    auto const* token = string_member(*root, "token");
    if (token == nullptr || token->empty())
    {
        return std::nullopt;
    }
    StoreInviteResponse out{};
    out.token = *token;
    if (auto const* display_name = string_member(*root, "display_name"); display_name != nullptr)
    {
        out.display_name = *display_name;
    }
    if (auto const* pks_value = object_member(*root, "public_keys"); pks_value != nullptr)
    {
        if (auto const* pks = std::get_if<canonicaljson::Array>(&pks_value->storage()); pks != nullptr)
        {
            for (auto const& entry : *pks)
            {
                auto const* entry_obj = std::get_if<canonicaljson::Object>(&entry.storage());
                if (entry_obj == nullptr)
                {
                    continue;
                }
                auto const* public_key = string_member(*entry_obj, "public_key");
                if (public_key == nullptr || public_key->empty())
                {
                    continue;
                }
                auto const* key_validity_url = string_member(*entry_obj, "key_validity_url");
                out.public_keys.push_back(
                    StoreInvitePublicKey{*public_key, key_validity_url != nullptr ? *key_validity_url : std::string{}});
            }
        }
    }
    return out;
}

auto parse_lookup_response(std::string_view body) -> std::optional<LookupResponse>
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return std::nullopt;
    }
    LookupResponse out{};
    if (auto const* mxid = string_member(*root, "mxid"); mxid != nullptr)
    {
        out.mxid = *mxid;
    }
    return out;
}

IdentityServerClient::IdentityServerClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                                           config::IdentityServerConfig const& config) noexcept
    : outbound_{outbound}
    , discovery_{discovery}
    , config_{config}
{
}

auto IdentityServerClient::perform(std::string_view base_url, std::string_view method, std::string_view path,
                                   std::string_view id_access_token, std::string_view body) -> IdentityServerResult
{
    auto const parsed = parse_identity_server_url(base_url);
    if (!parsed.has_value())
    {
        return {false, 0U, {}, http::OutboundError::invalid_url, "invalid identity server base URL"};
    }
    // SSRF-safe resolution: the cached discovery network applies the operator
    // deny_ip_ranges (private/loopback) before returning pinned addresses. We
    // never resolve DNS in the client or accept a client-supplied address.
    auto const resolved = discovery_.upstream().lookup_addresses(parsed->host, parsed->port);
    if (!resolved.ok || resolved.addresses.empty())
    {
        return {false,
                0U,
                {},
                http::OutboundError::unresolved_host,
                "SSRF-safe resolution failed for identity server host: " + resolved.reason};
    }

    // Build the full URL from the base URL (trimmed of trailing slash) + the
    // IS API path. The pinned addresses are bound to this URL's host:port by
    // the outbound client via CURLOPT_RESOLVE, so the connection cannot drift.
    auto url = std::string{base_url};
    while (!url.empty() && url.back() == '/')
    {
        url.pop_back();
    }
    url.append(path);

    auto request = http::OutboundRequest{};
    request.method = std::string{method};
    request.url = std::move(url);
    request.body = std::string{body};
    request.pinned_addresses = resolved.addresses;
    request.connect_timeout_seconds = config_.connect_timeout_seconds;
    request.total_timeout_seconds = config_.total_timeout_seconds;
    request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});
    if (!id_access_token.empty())
    {
        request.headers.push_back(http::OutboundHeader{"Authorization", "Bearer " + std::string{id_access_token}});
    }

    auto const result = outbound_.perform(request);
    if (!result.ok)
    {
        return {false, 0U, {}, result.error, result.error_detail};
    }
    return {true, result.response.status, result.response.body, http::OutboundError::none, {}};
}

auto IdentityServerClient::store_invite(std::string_view base_url, std::string_view id_access_token,
                                        std::string_view medium, std::string_view address, std::string_view room_id,
                                        std::string_view sender) -> IdentityServerResult
{
    return perform(base_url, "POST", "/_matrix/identity/v2/store-invite", id_access_token,
                   build_store_invite_body(medium, address, room_id, sender));
}

auto IdentityServerClient::lookup(std::string_view base_url, std::string_view medium, std::string_view address)
    -> IdentityServerResult
{
    return perform(base_url, "POST", "/_matrix/identity/v2/lookup", std::string_view{},
                   build_lookup_body(medium, address));
}

auto IdentityServerClient::bind(std::string_view base_url, std::string_view id_access_token,
                                std::string_view client_secret, std::string_view sid, std::string_view mxid)
    -> IdentityServerResult
{
    return perform(base_url, "POST", "/_matrix/identity/v2/3pid/bind", id_access_token,
                   build_bind_body(client_secret, sid, mxid));
}

auto IdentityServerClient::unbind(std::string_view base_url, std::string_view id_access_token,
                                  std::string_view client_secret, std::string_view sid, std::string_view medium,
                                  std::string_view address) -> IdentityServerResult
{
    return perform(base_url, "POST", "/_matrix/identity/v2/3pid/unbind", id_access_token,
                   build_unbind_body(client_secret, sid, medium, address));
}

auto IdentityServerClient::request_email_token(std::string_view base_url, std::string_view id_access_token,
                                               std::string_view client_secret, std::string_view email,
                                               std::string_view next_link) -> IdentityServerResult
{
    return perform(base_url, "POST", "/_matrix/identity/v2/validate/email/requestToken", id_access_token,
                   build_request_token_body(client_secret, email, next_link));
}

} // namespace merovingian::identity