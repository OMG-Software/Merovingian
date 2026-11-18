// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientUri.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::oauth
{

// Grant types this server knows (RFC 6749, RFC 8628). Any other value a client registers is ignored.
inline constexpr std::string_view grant_type_authorization_code = "authorization_code";
inline constexpr std::string_view grant_type_refresh_token = "refresh_token";
inline constexpr std::string_view grant_type_device_code = "urn:ietf:params:oauth:grant-type:device_code";
// The one response type this server knows.
inline constexpr std::string_view response_type_code = "code";
// The one token endpoint authentication method: every client is public.
inline constexpr std::string_view token_endpoint_auth_method_none = "none";

// The client metadata a registration request was accepted with (spec "Client metadata", RFC 7591; ADR-0771). Exists
// only through validate(), so every value satisfies the rules there; lists are deduplicated and in a fixed order.
class ClientMetadata final
{
public:
    // The most members read from the request object: a full registration has a dozen, and localised variants a few
    // more each.
    static constexpr std::size_t max_members = 128U;
    // The most redirect URIs: a client registers one or two.
    static constexpr std::size_t max_redirect_uris = 16U;
    // The most entries read from `grant_types` or `response_types`, known or not.
    static constexpr std::size_t max_type_entries = 16U;
    // The longest `client_name`, in bytes: what fits on one line of the consent page.
    static constexpr std::size_t max_client_name_bytes = 128U;

    // The metadata of a registration request body, already parsed as JSON, or a refusal:
    //
    //  - not an object, more than max_members members, a duplicated key, or a known key of the wrong JSON type:
    //    `invalid_client_metadata`.
    //  - `client_uri` (required): ClientUri::read, else `invalid_client_metadata`.
    //  - `application_type`: `web` (also when omitted) or `native`, else `invalid_client_metadata`.
    //  - `redirect_uris`: an array of at most max_redirect_uris strings. Each is checked by validate_redirect_uri and
    //    a failure is `invalid_redirect_uri`. Duplicates collapse and the result is sorted.
    //  - `grant_types`: `["authorization_code"]` when omitted. Unknown values are ignored and duplicates collapse.
    //    An array with no known value is `invalid_client_metadata`.
    //  - `response_types`: `["code"]` when omitted. Unknown values are ignored. With `authorization_code` registered,
    //    `code` and at least one redirect URI are required, else `invalid_client_metadata`.
    //  - `token_endpoint_auth_method`: omitted or `none`, else `invalid_client_metadata`.
    //  - `client_name`: 1 to max_client_name_bytes bytes passing display_text_is_safe, else
    //    `invalid_client_metadata`.
    //  - `policy_uri`, `tos_uri`: a ParsedUri accepted by https_uri_is_on_client_host, else
    //    `invalid_client_metadata`.
    //  - `logo_uri`, every localised key (`name#lang`) and every other key: ignored, never registered.
    [[nodiscard]] static auto validate(canonicaljson::Value const& request)
        -> std::variant<ClientMetadata, OAuthRefusal>;

    [[nodiscard]] auto client_uri() const noexcept -> ClientUri const&;
    [[nodiscard]] auto application_type() const noexcept -> ApplicationType;
    // Sorted, no duplicates; may be empty when `authorization_code` is not registered.
    [[nodiscard]] auto redirect_uris() const noexcept -> std::vector<std::string> const&;
    // Known values only, in the order authorization_code, refresh_token, device_code.
    [[nodiscard]] auto grant_types() const noexcept -> std::vector<std::string> const&;
    // `code` or nothing.
    [[nodiscard]] auto response_types() const noexcept -> std::vector<std::string> const&;
    [[nodiscard]] auto client_name() const noexcept -> std::optional<std::string> const&;
    [[nodiscard]] auto policy_uri() const noexcept -> std::optional<std::string> const&;
    [[nodiscard]] auto tos_uri() const noexcept -> std::optional<std::string> const&;
    [[nodiscard]] auto has_grant_type(std::string_view grant_type) const noexcept -> bool;

    // The registered metadata as the registration response's JSON object, without `client_id`: `application_type`,
    // `client_uri`, `grant_types`, `redirect_uris`, `response_types`, `token_endpoint_auth_method` (`none`), and
    // `client_name`, `policy_uri`, `tos_uri` when registered.
    [[nodiscard]] auto to_json() const -> canonicaljson::Value;

    // to_json() as canonical JSON: the same accepted metadata gives the same bytes whatever the key order, the
    // duplicate values or the ignored members of the request. The input of the client ID hash (phase 4).
    // ErrorCode::internal_failure only when the serializer refuses a value this class built.
    [[nodiscard]] auto canonical_bytes() const -> std::variant<std::string, core::Error>;

private:
    explicit ClientMetadata(ClientUri client_uri);

    ClientUri m_client_uri;
    ApplicationType m_application_type{ApplicationType::web};
    std::vector<std::string> m_redirect_uris{};
    std::vector<std::string> m_grant_types{};
    std::vector<std::string> m_response_types{};
    std::optional<std::string> m_client_name{};
    std::optional<std::string> m_policy_uri{};
    std::optional<std::string> m_tos_uri{};
};

} // namespace merovingian::oauth
