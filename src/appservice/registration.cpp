// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/registration.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/constant_time.hpp"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>

namespace merovingian::appservice
{
namespace
{

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        auto const it = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return it == object.end() ? nullptr : it->value.get();
    }

    [[nodiscard]] auto as_string(canonicaljson::Value const& value) noexcept -> std::string const*
    {
        return std::get_if<std::string>(&value.storage());
    }

    [[nodiscard]] auto as_bool(canonicaljson::Value const& value) noexcept -> bool const*
    {
        return std::get_if<bool>(&value.storage());
    }

    [[nodiscard]] auto as_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto as_array(canonicaljson::Value const& value) noexcept -> canonicaljson::Array const*
    {
        return std::get_if<canonicaljson::Array>(&value.storage());
    }

    [[nodiscard]] auto secret_from_string(std::string_view token) -> core::SecretBuffer
    {
        auto buffer = core::SecretBuffer{token.size()};
        std::copy(token.begin(), token.end(), buffer.bytes().begin());
        return buffer;
    }

    [[nodiscard]] auto secret_view(core::SecretBuffer const& secret) noexcept -> std::string_view
    {
        auto const bytes = secret.bytes();
        return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
    }

    // Parses one `namespaces.{users,aliases,rooms}` array entry list.
    [[nodiscard]] auto parse_namespace_array(canonicaljson::Object const& namespaces_obj, std::string_view key,
                                             std::vector<Namespace>& out, std::string& parse_error) -> bool
    {
        auto const* member = object_member(namespaces_obj, key);
        if (member == nullptr)
        {
            // All three arrays are optional (absence means "none").
            return true;
        }
        auto const* array = as_array(*member);
        if (array == nullptr)
        {
            parse_error = "namespaces." + std::string{key} + " must be an array";
            return false;
        }
        for (auto const& entry : *array)
        {
            auto const* entry_obj = as_object(entry);
            if (entry_obj == nullptr)
            {
                parse_error = "namespaces." + std::string{key} + " entries must be objects";
                return false;
            }
            auto const* regex_value = object_member(*entry_obj, "regex");
            auto const* regex_str = regex_value == nullptr ? nullptr : as_string(*regex_value);
            if (regex_str == nullptr)
            {
                parse_error = "namespaces." + std::string{key} + " entry missing required 'regex' string";
                return false;
            }
            auto const* exclusive_value = object_member(*entry_obj, "exclusive");
            auto const* exclusive_bool = exclusive_value == nullptr ? nullptr : as_bool(*exclusive_value);
            if (exclusive_bool == nullptr)
            {
                parse_error = "namespaces." + std::string{key} + " entry missing required 'exclusive' boolean";
                return false;
            }
            out.push_back(Namespace{*exclusive_bool, *regex_str});
        }
        return true;
    }

} // namespace

auto namespace_matches(std::string_view pattern, std::string_view value) noexcept -> bool
{
    try
    {
        auto const compiled = std::regex{pattern.begin(), pattern.end(), std::regex::extended};
        return std::regex_search(value.begin(), value.end(), compiled);
    }
    catch (std::regex_error const&)
    {
        // A malformed operator-supplied regex must never crash the request
        // path or be treated as "matches everything" — fail closed to "no
        // match". validate_registrations() surfaces malformed regexes as a
        // startup finding so operators notice long before this path runs.
        return false;
    }
}

auto any_namespace_matches(std::vector<Namespace> const& namespaces, std::string_view value) noexcept -> bool
{
    return std::ranges::any_of(namespaces, [value](Namespace const& ns) {
        return namespace_matches(ns.regex, value);
    });
}

auto any_exclusive_namespace_matches(std::vector<Namespace> const& namespaces, std::string_view value) noexcept -> bool
{
    return std::ranges::any_of(namespaces, [value](Namespace const& ns) {
        return ns.exclusive && namespace_matches(ns.regex, value);
    });
}

auto sender_user_id(AppserviceRegistration const& registration, std::string_view server_name) -> std::string
{
    return "@" + registration.sender_localpart + ":" + std::string{server_name};
}

auto appservice_owns_user(AppserviceRegistration const& registration, std::string_view server_name,
                          std::string_view user_id) noexcept -> bool
{
    if (sender_user_id(registration, server_name) == user_id)
    {
        return true;
    }
    return any_namespace_matches(registration.namespaces.users, user_id);
}

auto parse_registration_json(std::string_view json_text) -> AppserviceRegistrationParseResult
{
    auto const parsed = canonicaljson::parse_json(json_text);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::parse_failure, std::string{"registration file is not valid JSON: "} +
                                                            canonicaljson::parse_error_name(parsed.error)}
        };
    }
    auto const* root = as_object(parsed.value);
    if (root == nullptr)
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, "registration file must be a JSON object"}
        };
    }

    auto registration = AppserviceRegistration{};

    auto const* id_value = object_member(*root, "id");
    auto const* id_str = id_value == nullptr ? nullptr : as_string(*id_value);
    if (id_str == nullptr || id_str->empty())
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, "registration missing required 'id' string"}
        };
    }
    registration.id = *id_str;

    auto const* as_token_value = object_member(*root, "as_token");
    auto const* as_token_str = as_token_value == nullptr ? nullptr : as_string(*as_token_value);
    if (as_token_str == nullptr || as_token_str->empty())
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::parse_failure, "registration missing required 'as_token' string"}
        };
    }
    registration.as_token = secret_from_string(*as_token_str);

    auto const* hs_token_value = object_member(*root, "hs_token");
    auto const* hs_token_str = hs_token_value == nullptr ? nullptr : as_string(*hs_token_value);
    if (hs_token_str == nullptr || hs_token_str->empty())
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::parse_failure, "registration missing required 'hs_token' string"}
        };
    }
    registration.hs_token = secret_from_string(*hs_token_str);

    auto const* sender_localpart_value = object_member(*root, "sender_localpart");
    auto const* sender_localpart_str = sender_localpart_value == nullptr ? nullptr : as_string(*sender_localpart_value);
    if (sender_localpart_str == nullptr || sender_localpart_str->empty())
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::parse_failure, "registration missing required 'sender_localpart' string"}
        };
    }
    registration.sender_localpart = *sender_localpart_str;

    // `url` is required but may be JSON null ("no traffic is required").
    auto const* url_value = object_member(*root, "url");
    if (url_value == nullptr)
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, "registration missing required 'url' field"}
        };
    }
    if (auto const* url_str = as_string(*url_value); url_str != nullptr)
    {
        registration.url = *url_str;
    }
    else if (!std::holds_alternative<std::nullptr_t>(url_value->storage()))
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, "'url' must be a string or null"}
        };
    }

    auto const* namespaces_value = object_member(*root, "namespaces");
    auto const* namespaces_obj = namespaces_value == nullptr ? nullptr : as_object(*namespaces_value);
    if (namespaces_obj == nullptr)
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::parse_failure, "registration missing required 'namespaces' object"}
        };
    }
    auto parse_error = std::string{};
    if (!parse_namespace_array(*namespaces_obj, "users", registration.namespaces.users, parse_error) ||
        !parse_namespace_array(*namespaces_obj, "aliases", registration.namespaces.aliases, parse_error) ||
        !parse_namespace_array(*namespaces_obj, "rooms", registration.namespaces.rooms, parse_error))
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, parse_error}
        };
    }

    if (auto const* protocols_value = object_member(*root, "protocols"); protocols_value != nullptr)
    {
        if (auto const* protocols_array = as_array(*protocols_value); protocols_array != nullptr)
        {
            for (auto const& entry : *protocols_array)
            {
                if (auto const* protocol_str = as_string(entry); protocol_str != nullptr)
                {
                    registration.protocols.push_back(*protocol_str);
                }
            }
        }
    }
    if (auto const* rate_limited_value = object_member(*root, "rate_limited"); rate_limited_value != nullptr)
    {
        if (auto const* rate_limited_bool = as_bool(*rate_limited_value); rate_limited_bool != nullptr)
        {
            registration.rate_limited = *rate_limited_bool;
        }
    }
    if (auto const* receive_ephemeral_value = object_member(*root, "receive_ephemeral");
        receive_ephemeral_value != nullptr)
    {
        if (auto const* receive_ephemeral_bool = as_bool(*receive_ephemeral_value); receive_ephemeral_bool != nullptr)
        {
            registration.receive_ephemeral = *receive_ephemeral_bool;
        }
    }

    return {std::move(registration), core::Error{}};
}

auto load_registration_file(std::string_view path) -> AppserviceRegistrationParseResult
{
    auto stream = std::ifstream{std::string{path}, std::ios::binary};
    if (!stream.is_open())
    {
        return {
            std::nullopt,
            core::Error{core::ErrorCode::io_failure, "cannot open appservice registration file: " + std::string{path}}
        };
    }
    auto buffer = std::ostringstream{};
    buffer << stream.rdbuf();
    if (stream.bad())
    {
        return {
            std::nullopt, core::Error{core::ErrorCode::io_failure,
                                      "failed reading appservice registration file: " + std::string{path}}
        };
    }
    return parse_registration_json(buffer.str());
}

AppserviceRegistry::AppserviceRegistry(std::vector<AppserviceRegistration> registrations) noexcept
    : m_registrations{std::move(registrations)}
{
}

auto AppserviceRegistry::empty() const noexcept -> bool
{
    return m_registrations.empty();
}

auto AppserviceRegistry::size() const noexcept -> std::size_t
{
    return m_registrations.size();
}

auto AppserviceRegistry::all() const noexcept -> std::vector<AppserviceRegistration> const&
{
    return m_registrations;
}

auto AppserviceRegistry::find_by_as_token(std::string_view presented_token) const noexcept
    -> AppserviceRegistration const*
{
    if (presented_token.empty())
    {
        return nullptr;
    }
    for (auto const& registration : m_registrations)
    {
        if (crypto::constant_time_equal_variable_length(presented_token, secret_view(registration.as_token)))
        {
            return &registration;
        }
    }
    return nullptr;
}

auto AppserviceRegistry::find_by_id(std::string_view id) const noexcept -> AppserviceRegistration const*
{
    auto const it = std::ranges::find_if(m_registrations, [id](AppserviceRegistration const& reg) {
        return reg.id == id;
    });
    return it == m_registrations.end() ? nullptr : &(*it);
}

auto AppserviceRegistry::user_namespace_exclusively_owned_by_other(std::string_view user_id,
                                                                   std::string_view excluded_id) const noexcept -> bool
{
    return std::ranges::any_of(m_registrations, [user_id, excluded_id](AppserviceRegistration const& reg) {
        return reg.id != excluded_id && any_exclusive_namespace_matches(reg.namespaces.users, user_id);
    });
}

auto AppserviceRegistry::alias_namespace_exclusively_owned_by_other(std::string_view alias,
                                                                    std::string_view excluded_id) const noexcept -> bool
{
    return std::ranges::any_of(m_registrations, [alias, excluded_id](AppserviceRegistration const& reg) {
        return reg.id != excluded_id && any_exclusive_namespace_matches(reg.namespaces.aliases, alias);
    });
}

namespace
{
    [[nodiscard]] auto regex_is_valid(std::string_view pattern) noexcept -> bool
    {
        try
        {
            std::ignore = std::regex{pattern.begin(), pattern.end(), std::regex::extended};
            return true;
        }
        catch (std::regex_error const&)
        {
            return false;
        }
    }

    auto validate_namespace_regexes(std::vector<Namespace> const& entries, std::string_view kind,
                                    std::string_view registration_id,
                                    std::vector<AppserviceRegistrationFinding>& findings) -> void
    {
        for (auto const& entry : entries)
        {
            if (!regex_is_valid(entry.regex))
            {
                findings.push_back({std::string{registration_id}, "invalid POSIX regular expression in namespaces." +
                                                                      std::string{kind} + ": " + entry.regex});
            }
        }
    }
} // namespace

auto validate_registrations(std::vector<AppserviceRegistration> const& registrations)
    -> std::vector<AppserviceRegistrationFinding>
{
    auto findings = std::vector<AppserviceRegistrationFinding>{};

    for (auto const& registration : registrations)
    {
        validate_namespace_regexes(registration.namespaces.users, "users", registration.id, findings);
        validate_namespace_regexes(registration.namespaces.aliases, "aliases", registration.id, findings);
        validate_namespace_regexes(registration.namespaces.rooms, "rooms", registration.id, findings);
    }

    // Spec v1.19: "each as_token and id MUST be unique per application
    // service ... The homeserver MUST enforce this." Checked pairwise;
    // as_token comparisons stay constant-time even though this only runs at
    // startup, so the same primitive is used everywhere a token is compared.
    for (std::size_t i = 0U; i < registrations.size(); ++i)
    {
        for (std::size_t j = i + 1U; j < registrations.size(); ++j)
        {
            if (registrations[i].id == registrations[j].id)
            {
                findings.push_back({registrations[j].id, "duplicate appservice id: " + registrations[j].id});
            }
            if (crypto::constant_time_equal_variable_length(secret_view(registrations[i].as_token),
                                                            secret_view(registrations[j].as_token)))
            {
                findings.push_back(
                    {registrations[j].id, "duplicate as_token shared with appservice '" + registrations[i].id + "'"});
            }
        }
    }

    return findings;
}

auto load_registrations(std::vector<std::string> const& paths) -> LoadRegistrationsResult
{
    auto result = LoadRegistrationsResult{};
    auto loaded = std::vector<AppserviceRegistration>{};

    for (auto const& path : paths)
    {
        auto parsed = load_registration_file(path);
        if (!parsed.value.has_value())
        {
            result.findings.push_back({path, parsed.error.message()});
            continue;
        }
        loaded.push_back(std::move(*parsed.value));
    }

    auto const cross_findings = validate_registrations(loaded);
    if (!cross_findings.empty())
    {
        // Duplicate id/as_token makes routing ambiguous — fail closed for
        // the WHOLE set rather than guessing which registration "wins".
        for (auto const& finding : cross_findings)
        {
            result.findings.push_back(finding);
        }
        result.registry = AppserviceRegistry{};
        return result;
    }

    result.registry = AppserviceRegistry{std::move(loaded)};
    return result;
}

} // namespace merovingian::appservice
