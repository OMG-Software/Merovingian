// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/ServerAcl.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/federation/Security.hpp"
#include "merovingian/federation/ServerAclDecision.hpp"
#include "merovingian/federation/ServerAclEvaluation.hpp"
#include "merovingian/federation/ServerAclEvent.hpp"
#include "merovingian/federation/ServerAclGlob.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::federation
{
namespace
{

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

    // Past the caps the ACL is not evaluated pattern by pattern: it refuses every server (ADR-0640).
    auto const over_length = [](std::string const& pattern) noexcept {
        return pattern.size() > server_acl_max_pattern_length;
    };
    if (result.allow.size() + result.deny.size() > server_acl_max_patterns ||
        std::ranges::any_of(result.allow, over_length) || std::ranges::any_of(result.deny, over_length))
    {
        result.allow.clear();
        result.deny.clear();
        result.exceeds_limits = true;
    }
    return result;
}

auto evaluate_server_acl(std::string_view server_name, ServerAclEvent const& acl) -> ServerAclEvaluation
{
    auto const host = strip_server_port(server_name);
    if (host.empty())
    {
        return {ServerAclDecision::deny, "empty_server_name", "server name is empty after port stripping"};
    }

    if (acl.exceeds_limits)
    {
        return {ServerAclDecision::deny, "acl_limits", "the ACL has more or longer patterns than the server evaluates"};
    }

    if (!acl.allow_ip_literals && server_name_is_ip_literal(host))
    {
        return {ServerAclDecision::deny, "allow_ip_literals",
                "server name is an IP literal and allow_ip_literals is false"};
    }

    auto steps_left = server_acl_max_glob_steps;
    for (auto const& pattern : acl.deny)
    {
        auto const matched = server_acl_glob_match(pattern, host, steps_left);
        if (!matched.has_value())
        {
            return {ServerAclDecision::deny, "acl_budget", "the ACL check used up its step budget"};
        }
        if (*matched)
        {
            return {ServerAclDecision::deny, "deny", "server name matches deny list entry: " + pattern};
        }
    }

    for (auto const& pattern : acl.allow)
    {
        auto const matched = server_acl_glob_match(pattern, host, steps_left);
        if (!matched.has_value())
        {
            return {ServerAclDecision::deny, "acl_budget", "the ACL check used up its step budget"};
        }
        if (*matched)
        {
            return {ServerAclDecision::allow, "allow", "server name matches allow list entry: " + pattern};
        }
    }

    return {ServerAclDecision::deny, "allow", "server name did not match any allow list entry"};
}

namespace
{

    // The parsed ACL is immutable and shared: the owners are the cache and the callers mid-check, unique ownership
    // would copy the pattern lists on every lookup, and it holds no reference back to the cache or the store, so there
    // is no cycle.
    using SharedServerAcl = std::shared_ptr<ServerAclEvent const>; // SHARED_PTR: reviewed — immutable, see above

    // A parsed ACL kept for the event that holds it (ADR-0640). The ACL of an event is a pure function of the event's
    // JSON, but a redaction rewrites that JSON under the same event ID, so an entry also records the JSON's size and
    // hash and is used only while both still match.
    struct CachedServerAcl final
    {
        std::size_t json_size{0U};
        std::size_t json_hash{0U};
        SharedServerAcl acl{};
    };

    // Synchronised and bounded (ADR-0525): one mutex guards the map, and it is emptied when it reaches its cap.
    class ServerAclCache final
    {
    public:
        [[nodiscard]] auto find(std::string const& event_id, std::size_t json_size, std::size_t json_hash)
            -> SharedServerAcl
        {
            auto const lock = std::scoped_lock{m_mutex};
            auto const entry = m_entries.find(event_id);
            if (entry == m_entries.end() || entry->second.json_size != json_size ||
                entry->second.json_hash != json_hash)
            {
                return nullptr;
            }
            return entry->second.acl;
        }

        auto remember(std::string const& event_id, std::size_t json_size, std::size_t json_hash, SharedServerAcl acl)
            -> void
        {
            auto const lock = std::scoped_lock{m_mutex};
            if (m_entries.size() >= max_entries && !m_entries.contains(event_id))
            {
                m_entries.clear();
            }
            m_entries.insert_or_assign(event_id, CachedServerAcl{json_size, json_hash, std::move(acl)});
        }

        static constexpr auto max_entries = std::size_t{256U};

    private:
        std::mutex m_mutex{};
        std::unordered_map<std::string, CachedServerAcl> m_entries{};
    };

    ServerAclCache server_acl_cache{};

    // The room's current ACL, parsed once per ACL event, or null when the room has none (or it cannot be read).
    [[nodiscard]] auto current_server_acl(database::PersistentStore const& store, std::string_view room_id)
        -> SharedServerAcl
    {
        // The state index (ADR-0344): the ACL is read for every PDU and every room-scoped request, and main
        // reads it under runtime.mutex, so it must not cost a scan of the server's whole state.
        auto const acl_event_id = database::find_current_state_event_id(store, room_id, "m.room.server_acl", "");
        if (!acl_event_id.has_value() || acl_event_id->empty())
        {
            return nullptr;
        }

        auto const event = store.events.find(*acl_event_id);
        if (event == store.events.end())
        {
            return nullptr;
        }
        auto const json_size = event->json.size();
        auto const json_hash = std::hash<std::string_view>{}(event->json);
        if (auto cached = server_acl_cache.find(*acl_event_id, json_size, json_hash); cached != nullptr)
        {
            return cached;
        }

        auto const parsed = canonicaljson::parse_lossless(event->json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return nullptr;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return nullptr;
        }
        auto const* content = object_member(*object, "content");
        if (content == nullptr)
        {
            return nullptr;
        }
        auto acl = SharedServerAcl{std::make_shared<ServerAclEvent const>(
            parse_server_acl(*content))}; // SHARED_PTR: reviewed — see SharedServerAcl
        server_acl_cache.remember(*acl_event_id, json_size, json_hash, acl);
        return acl;
    }

} // namespace

auto load_room_server_acl(database::PersistentStore const& store, std::string_view room_id)
    -> std::optional<ServerAclEvent>
{
    auto const acl = current_server_acl(store, room_id);
    if (acl == nullptr)
    {
        return std::nullopt;
    }
    return *acl;
}

auto room_server_acl_allows(database::PersistentStore const& store, std::string_view room_id,
                            std::string_view server_name) -> bool
{
    auto const acl = current_server_acl(store, room_id);
    if (acl == nullptr)
    {
        return true;
    }
    return evaluate_server_acl(server_name, *acl).decision == ServerAclDecision::allow;
}

} // namespace merovingian::federation
