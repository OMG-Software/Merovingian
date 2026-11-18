// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/ClientMetadata.hpp"

#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/DisplayText.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/RedirectUriRules.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace merovingian::oauth
{
namespace
{

    using canonicaljson::Array;
    using canonicaljson::Object;
    using canonicaljson::Value;

    [[nodiscard]] auto refuse(core::ErrorCode code, char const* message) -> OAuthRefusal
    {
        return OAuthRefusal{
            std::string{error_invalid_client_metadata},
            core::Error{code, message}
        };
    }

    [[nodiscard]] auto wrong_type() -> OAuthRefusal
    {
        return refuse(core::ErrorCode::parse_failure, "A client metadata value has the wrong JSON type.");
    }

    // The members validate() reads; every other member is ignored.
    struct KnownMembers final
    {
        Value const* client_uri{nullptr};
        Value const* application_type{nullptr};
        Value const* redirect_uris{nullptr};
        Value const* grant_types{nullptr};
        Value const* response_types{nullptr};
        Value const* token_endpoint_auth_method{nullptr};
        Value const* client_name{nullptr};
        Value const* policy_uri{nullptr};
        Value const* tos_uri{nullptr};
    };

    [[nodiscard]] auto pick(KnownMembers& known, std::string_view key) -> Value const**
    {
        if (key == "client_uri")
        {
            return &known.client_uri;
        }
        if (key == "application_type")
        {
            return &known.application_type;
        }
        if (key == "redirect_uris")
        {
            return &known.redirect_uris;
        }
        if (key == "grant_types")
        {
            return &known.grant_types;
        }
        if (key == "response_types")
        {
            return &known.response_types;
        }
        if (key == "token_endpoint_auth_method")
        {
            return &known.token_endpoint_auth_method;
        }
        if (key == "client_name")
        {
            return &known.client_name;
        }
        if (key == "policy_uri")
        {
            return &known.policy_uri;
        }
        if (key == "tos_uri")
        {
            return &known.tos_uri;
        }
        return nullptr;
    }

    [[nodiscard]] auto as_string(Value const* value) -> std::string const*
    {
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    // The strings of an array of at most `cap` strings; nullopt when it is not one. `too_many` says why.
    [[nodiscard]] auto string_array(Value const& value, std::size_t cap, bool& too_many)
        -> std::optional<std::vector<std::string>>
    {
        auto const* array = std::get_if<Array>(&value.storage());
        if (array == nullptr)
        {
            return std::nullopt;
        }
        if (array->size() > cap)
        {
            too_many = true;
            return std::nullopt;
        }
        auto strings = std::vector<std::string>{};
        strings.reserve(array->size());
        for (auto const& entry : *array)
        {
            auto const* text = std::get_if<std::string>(&entry.storage());
            if (text == nullptr)
            {
                return std::nullopt;
            }
            strings.push_back(*text);
        }
        return strings;
    }

    [[nodiscard]] auto contains(std::vector<std::string> const& values, std::string_view wanted) -> bool
    {
        return std::ranges::find(values, wanted) != values.end();
    }

    [[nodiscard]] auto string_list(std::vector<std::string> const& values) -> Value
    {
        auto array = Array{};
        array.reserve(values.size());
        for (auto const& value : values)
        {
            array.emplace_back(value);
        }
        return Value{std::move(array)};
    }

    [[nodiscard]] auto read_on_client_host(std::string const& text, ClientUri const& client_uri) -> bool
    {
        auto parsed = ParsedUri::read(text);
        auto const* uri = std::get_if<ParsedUri>(&parsed);
        return uri != nullptr && https_uri_is_on_client_host(*uri, client_uri);
    }

} // namespace

ClientMetadata::ClientMetadata(ClientUri client_uri)
    : m_client_uri{std::move(client_uri)}
{
}

auto ClientMetadata::validate(canonicaljson::Value const& request) -> std::variant<ClientMetadata, OAuthRefusal>
{
    // The shape of the document first. The member cap bounds every loop below, and a repeated key is refused rather
    // than resolved, so the client and this server cannot disagree about which of two values was registered.
    auto const* object = std::get_if<Object>(&request.storage());
    if (object == nullptr)
    {
        return refuse(core::ErrorCode::parse_failure, "The client metadata must be a JSON object.");
    }
    if (object->size() > max_members)
    {
        return refuse(core::ErrorCode::invalid_argument, "The client metadata has too many members.");
    }
    if (canonicaljson::object_has_duplicate_keys(*object))
    {
        return refuse(core::ErrorCode::parse_failure, "The client metadata repeats a key.");
    }

    // Only the keys this server acts on are picked out. Every other key, `logo_uri` and the localised `name#lang`
    // forms included, is left behind and is never stored or returned.
    auto known = KnownMembers{};
    for (auto const& member : *object)
    {
        if (auto** slot = pick(known, member.key); slot != nullptr)
        {
            if (member.value == nullptr)
            {
                return wrong_type();
            }
            *slot = member.value.get();
        }
    }

    // client_uri first: every other address is checked against it.
    if (known.client_uri == nullptr)
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri is required.");
    }
    auto const* client_uri_text = as_string(known.client_uri);
    if (client_uri_text == nullptr)
    {
        return wrong_type();
    }
    auto client_uri = ClientUri::read(*client_uri_text);
    if (auto* refusal = std::get_if<OAuthRefusal>(&client_uri))
    {
        return std::move(*refusal);
    }
    auto metadata = ClientMetadata{std::move(std::get<ClientUri>(client_uri))};

    // `web` when omitted, as the spec's client metadata table says. The type is read before the redirect URIs
    // because it decides which forms of redirect URI the client may register.
    if (known.application_type != nullptr)
    {
        auto const* type = as_string(known.application_type);
        if (type == nullptr)
        {
            return wrong_type();
        }
        if (*type == "native")
        {
            metadata.m_application_type = ApplicationType::native;
        }
        else if (*type != "web")
        {
            return refuse(core::ErrorCode::parse_failure, "The application_type must be web or native.");
        }
    }

    // Only public clients exist here: a client that asks for a secret-based method is refused rather than
    // registered as `none` without being told.
    if (known.token_endpoint_auth_method != nullptr)
    {
        auto const* method = as_string(known.token_endpoint_auth_method);
        if (method == nullptr)
        {
            return wrong_type();
        }
        if (*method != token_endpoint_auth_method_none)
        {
            return refuse(core::ErrorCode::parse_failure, "The token_endpoint_auth_method must be none.");
        }
    }

    if (known.redirect_uris != nullptr)
    {
        auto too_many = false;
        auto uris = string_array(*known.redirect_uris, max_redirect_uris, too_many);
        if (too_many)
        {
            return refuse(core::ErrorCode::invalid_argument, "There are too many redirect_uris.");
        }
        if (!uris.has_value())
        {
            return wrong_type();
        }
        // One bad URI refuses the whole registration: a client is never registered with part of what it asked for.
        for (auto const& uri : *uris)
        {
            auto validated = validate_redirect_uri(uri, metadata.m_application_type, metadata.m_client_uri);
            if (auto* refusal = std::get_if<OAuthRefusal>(&validated))
            {
                return std::move(*refusal);
            }
        }
        // Sorted and deduplicated so that the same set in any order gives the same canonical bytes, and so the same
        // client ID (ADR-0779).
        std::ranges::sort(*uris);
        auto const duplicates = std::ranges::unique(*uris);
        uris->erase(duplicates.begin(), duplicates.end());
        metadata.m_redirect_uris = std::move(*uris);
    }

    // `["authorization_code"]` when omitted (RFC 7591 section 2). Unknown grant types are dropped, not refused,
    // and the known ones are stored in one fixed order, again for the canonical form.
    auto requested_grants = std::vector<std::string>{std::string{grant_type_authorization_code}};
    if (known.grant_types != nullptr)
    {
        auto too_many = false;
        auto grants = string_array(*known.grant_types, max_type_entries, too_many);
        if (too_many)
        {
            return refuse(core::ErrorCode::invalid_argument, "There are too many grant_types.");
        }
        if (!grants.has_value())
        {
            return wrong_type();
        }
        requested_grants = std::move(*grants);
    }
    for (auto const known_grant :
         std::array{grant_type_authorization_code, grant_type_refresh_token, grant_type_device_code})
    {
        if (contains(requested_grants, known_grant))
        {
            metadata.m_grant_types.emplace_back(known_grant);
        }
    }
    if (metadata.m_grant_types.empty())
    {
        return refuse(core::ErrorCode::parse_failure, "The grant_types hold no grant type this server supports.");
    }

    // `["code"]` when omitted. `code` is the only response type this server issues; any other is dropped.
    auto requested_responses = std::vector<std::string>{std::string{response_type_code}};
    if (known.response_types != nullptr)
    {
        auto too_many = false;
        auto responses = string_array(*known.response_types, max_type_entries, too_many);
        if (too_many)
        {
            return refuse(core::ErrorCode::invalid_argument, "There are too many response_types.");
        }
        if (!responses.has_value())
        {
            return wrong_type();
        }
        requested_responses = std::move(*responses);
    }
    if (contains(requested_responses, response_type_code))
    {
        metadata.m_response_types.emplace_back(response_type_code);
    }

    // The pieces must agree: a client that may use the authorization code grant needs the `code` response type
    // and somewhere to be sent back to. A client with only the device grant needs neither.
    if (metadata.has_grant_type(grant_type_authorization_code))
    {
        if (metadata.m_response_types.empty())
        {
            return refuse(core::ErrorCode::parse_failure, "The authorization_code grant needs the code response type.");
        }
        if (metadata.m_redirect_uris.empty())
        {
            return refuse(core::ErrorCode::parse_failure,
                          "The authorization_code grant needs at least one redirect URI.");
        }
    }

    // The name is shown to the user on the consent page, so it is bounded to one line and may hold no control,
    // bidirectional or invisible character that could disguise it.
    if (known.client_name != nullptr)
    {
        auto const* name = as_string(known.client_name);
        if (name == nullptr)
        {
            return wrong_type();
        }
        if (name->size() > max_client_name_bytes)
        {
            return refuse(core::ErrorCode::invalid_argument, "The client_name is too long.");
        }
        if (name->empty() || !display_text_is_safe(*name))
        {
            return refuse(core::ErrorCode::parse_failure,
                          "The client_name must be non-empty UTF-8 text without control characters.");
        }
        metadata.m_client_name = *name;
    }

    // The policy and terms links are shown beside the name, so each must be `https` on the client's own host or a
    // subdomain of it: a client cannot lend itself another site's standing.
    for (auto const& [value, target] : std::array{
             std::pair{known.policy_uri, &metadata.m_policy_uri},
             std::pair{known.tos_uri,    &metadata.m_tos_uri   }
    })
    {
        if (value == nullptr)
        {
            continue;
        }
        auto const* text = as_string(value);
        if (text == nullptr)
        {
            return wrong_type();
        }
        if (!read_on_client_host(*text, metadata.m_client_uri))
        {
            return refuse(core::ErrorCode::parse_failure,
                          "The policy_uri and tos_uri must be https on the client_uri host or a subdomain of it.");
        }
        *target = *text;
    }

    return metadata;
}

auto ClientMetadata::client_uri() const noexcept -> ClientUri const&
{
    return m_client_uri;
}

auto ClientMetadata::application_type() const noexcept -> ApplicationType
{
    return m_application_type;
}

auto ClientMetadata::redirect_uris() const noexcept -> std::vector<std::string> const&
{
    return m_redirect_uris;
}

auto ClientMetadata::grant_types() const noexcept -> std::vector<std::string> const&
{
    return m_grant_types;
}

auto ClientMetadata::response_types() const noexcept -> std::vector<std::string> const&
{
    return m_response_types;
}

auto ClientMetadata::client_name() const noexcept -> std::optional<std::string> const&
{
    return m_client_name;
}

auto ClientMetadata::policy_uri() const noexcept -> std::optional<std::string> const&
{
    return m_policy_uri;
}

auto ClientMetadata::tos_uri() const noexcept -> std::optional<std::string> const&
{
    return m_tos_uri;
}

auto ClientMetadata::has_grant_type(std::string_view grant_type) const noexcept -> bool
{
    return std::ranges::find(m_grant_types, grant_type) != m_grant_types.end();
}

auto ClientMetadata::to_json() const -> canonicaljson::Value
{
    auto object = Object{};
    object.push_back(canonicaljson::make_member(
        "application_type", Value{std::string{m_application_type == ApplicationType::native ? "native" : "web"}}));
    if (m_client_name.has_value())
    {
        object.push_back(canonicaljson::make_member("client_name", Value{*m_client_name}));
    }
    object.push_back(canonicaljson::make_member("client_uri", Value{m_client_uri.uri().text()}));
    object.push_back(canonicaljson::make_member("grant_types", string_list(m_grant_types)));
    if (m_policy_uri.has_value())
    {
        object.push_back(canonicaljson::make_member("policy_uri", Value{*m_policy_uri}));
    }
    object.push_back(canonicaljson::make_member("redirect_uris", string_list(m_redirect_uris)));
    object.push_back(canonicaljson::make_member("response_types", string_list(m_response_types)));
    object.push_back(
        canonicaljson::make_member("token_endpoint_auth_method", Value{std::string{token_endpoint_auth_method_none}}));
    if (m_tos_uri.has_value())
    {
        object.push_back(canonicaljson::make_member("tos_uri", Value{*m_tos_uri}));
    }
    return Value{std::move(object)};
}

auto ClientMetadata::canonical_bytes() const -> std::variant<std::string, core::Error>
{
    auto serialized = canonicaljson::serialize_canonical(to_json());
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return core::Error{core::ErrorCode::internal_failure, "The client metadata could not be serialised."};
    }
    return std::move(serialized.output);
}

} // namespace merovingian::oauth
