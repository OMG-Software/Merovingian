// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_acl.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/security.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto to_lower_ascii(char character) noexcept -> char
    {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }

    [[nodiscard]] auto case_insensitive_equal(char left, char right) noexcept -> bool
    {
        return to_lower_ascii(left) == to_lower_ascii(right);
    }

    // Matrix v1.19 glob matching: '*' matches zero or more characters, '?'
    // matches exactly one character. Matching is case-insensitive and applies
    // to the full server name, not a substring.
    [[nodiscard]] auto glob_match(std::string_view pattern, std::string_view text) noexcept -> bool
    {
        auto const pattern_length = pattern.size();
        auto const text_length = text.size();
        if (pattern_length == 0U)
        {
            return text_length == 0U;
        }

        auto previous = std::vector<bool>(text_length + 1U, false);
        auto current = std::vector<bool>(text_length + 1U, false);
        previous[0U] = true;

        for (auto pattern_index = std::size_t{1U}; pattern_index <= pattern_length; ++pattern_index)
        {
            auto const pattern_char = pattern[pattern_index - 1U];
            std::fill(current.begin(), current.end(), false);

            if (pattern_char == '*')
            {
                // '*' can match the empty prefix (carry previous[0]) or any
                // additional text character (carry current[text_index-1]).
                current[0U] = previous[0U];
                for (auto text_index = std::size_t{1U}; text_index <= text_length; ++text_index)
                {
                    current[text_index] = previous[text_index] || current[text_index - 1U];
                }
            }
            else if (pattern_char == '?')
            {
                for (auto text_index = std::size_t{1U}; text_index <= text_length; ++text_index)
                {
                    current[text_index] = previous[text_index - 1U];
                }
            }
            else
            {
                for (auto text_index = std::size_t{1U}; text_index <= text_length; ++text_index)
                {
                    if (case_insensitive_equal(pattern_char, text[text_index - 1U]))
                    {
                        current[text_index] = previous[text_index - 1U];
                    }
                }
            }
            previous.swap(current);
        }

        return previous[text_length];
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

    [[nodiscard]] auto bool_member(canonicaljson::Object const& object, std::string_view key) noexcept -> bool const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<bool>(&value->storage());
    }

    [[nodiscard]] auto string_array_member(canonicaljson::Object const& object, std::string_view key)
        -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return result;
        }
        auto const* array = std::get_if<canonicaljson::Array>(&value->storage());
        if (array == nullptr)
        {
            return result;
        }
        result.reserve(array->size());
        for (auto const& element : *array)
        {
            auto const* text = std::get_if<std::string>(&element.storage());
            if (text != nullptr)
            {
                result.push_back(*text);
            }
        }
        return result;
    }

    [[nodiscard]] auto host_without_brackets(std::string_view host) noexcept -> std::string_view
    {
        if (host.size() >= 2U && host.front() == '[' && host.back() == ']')
        {
            return host.substr(1U, host.size() - 2U);
        }
        return host;
    }

} // namespace

auto strip_server_port(std::string_view server_name) noexcept -> std::string
{
    if (server_name.empty())
    {
        return {};
    }

    // Bracketed IPv6 literal, optionally followed by ":port".
    if (server_name.front() == '[')
    {
        auto const close = server_name.find(']');
        if (close == std::string_view::npos)
        {
            return std::string{server_name};
        }
        return std::string{server_name.substr(0U, close + 1U)};
    }

    auto const colon = server_name.rfind(':');
    if (colon == std::string_view::npos || colon == 0U)
    {
        return std::string{server_name};
    }
    auto const port_part = server_name.substr(colon + 1U);
    auto const all_digits = std::ranges::all_of(port_part, [](char character) noexcept {
        return character >= '0' && character <= '9';
    });
    if (!all_digits)
    {
        return std::string{server_name};
    }
    return std::string{server_name.substr(0U, colon)};
}

auto server_name_is_ip_literal(std::string_view server_name) noexcept -> bool
{
    auto const host = strip_server_port(server_name);
    if (host.empty())
    {
        return false;
    }
    return ip_address_is_valid(host_without_brackets(host));
}

auto parse_server_acl(canonicaljson::Value const& content) -> ServerAclEvent
{
    auto result = ServerAclEvent{};
    auto const* object = std::get_if<canonicaljson::Object>(&content.storage());
    if (object == nullptr)
    {
        return result;
    }

    auto const* allow_ip_literals = bool_member(*object, "allow_ip_literals");
    if (allow_ip_literals != nullptr)
    {
        result.allow_ip_literals = *allow_ip_literals;
    }

    result.allow = string_array_member(*object, "allow");
    result.deny = string_array_member(*object, "deny");
    return result;
}

auto evaluate_server_acl(std::string_view server_name, ServerAclEvent const& acl) -> ServerAclEvaluation
{
    auto const host = strip_server_port(server_name);
    if (host.empty())
    {
        return {ServerAclDecision::deny, "empty_server_name", "server name is empty after port stripping"};
    }

    if (!acl.allow_ip_literals && server_name_is_ip_literal(host))
    {
        return {ServerAclDecision::deny, "allow_ip_literals",
                "server name is an IP literal and allow_ip_literals is false"};
    }

    for (auto const& pattern : acl.deny)
    {
        if (glob_match(pattern, host))
        {
            return {ServerAclDecision::deny, "deny", "server name matches deny list entry: " + pattern};
        }
    }

    for (auto const& pattern : acl.allow)
    {
        if (glob_match(pattern, host))
        {
            return {ServerAclDecision::allow, "allow", "server name matches allow list entry: " + pattern};
        }
    }

    if (acl.allow.empty())
    {
        return {ServerAclDecision::allow, "empty_allow",
                "allow list is empty and server name did not match any deny list entry; allowing"};
    }
    return {ServerAclDecision::deny, "allow", "server name did not match any allow list entry"};
}

auto load_room_server_acl(database::PersistentStore const& store, std::string_view room_id)
    -> std::optional<ServerAclEvent>
{
    auto acl_event_id = std::string_view{};
    for (auto const& state : store.state)
    {
        if (state.room_id == room_id && state.event_type == "m.room.server_acl" && state.state_key.empty())
        {
            acl_event_id = state.event_id;
            break;
        }
    }
    if (acl_event_id.empty())
    {
        return std::nullopt;
    }

    for (auto const& event : store.events)
    {
        if (event.event_id != acl_event_id)
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* content = object_member(*object, "content");
        if (content == nullptr)
        {
            return std::nullopt;
        }
        return parse_server_acl(*content);
    }

    return std::nullopt;
}

auto room_server_acl_allows(database::PersistentStore const& store, std::string_view room_id,
                            std::string_view server_name) -> bool
{
    auto const acl = load_room_server_acl(store, room_id);
    if (!acl.has_value())
    {
        return true;
    }
    return evaluate_server_acl(server_name, *acl).decision == ServerAclDecision::allow;
}

} // namespace merovingian::federation
