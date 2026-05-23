// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_filter.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::sync
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("sync_filter", event, std::move(fields)));
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto as_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto as_string(canonicaljson::Value const& value) noexcept -> std::string const*
    {
        return std::get_if<std::string>(&value.storage());
    }

    [[nodiscard]] auto as_integer(canonicaljson::Value const& value) noexcept -> std::int64_t const*
    {
        return std::get_if<std::int64_t>(&value.storage());
    }

    [[nodiscard]] auto as_boolean(canonicaljson::Value const& value) noexcept -> bool const*
    {
        return std::get_if<bool>(&value.storage());
    }

    [[nodiscard]] auto extract_strings(canonicaljson::Value const& value) -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        auto const* array = std::get_if<canonicaljson::Array>(&value.storage());
        if (array == nullptr)
        {
            return out;
        }
        for (auto const& entry : *array)
        {
            if (auto const* text = as_string(entry); text != nullptr && !text->empty())
            {
                out.push_back(*text);
            }
        }
        return out;
    }

    auto populate_event_filter(EventTypeFilter& target, canonicaljson::Object const& source) -> void
    {
        if (auto const* types = find_member(source, "types"); types != nullptr)
        {
            target.types = extract_strings(*types);
        }
        if (auto const* not_types = find_member(source, "not_types"); not_types != nullptr)
        {
            target.not_types = extract_strings(*not_types);
        }
        if (auto const* senders = find_member(source, "senders"); senders != nullptr)
        {
            target.senders = extract_strings(*senders);
        }
        if (auto const* not_senders = find_member(source, "not_senders"); not_senders != nullptr)
        {
            target.not_senders = extract_strings(*not_senders);
        }
        if (auto const* limit = find_member(source, "limit"); limit != nullptr)
        {
            if (auto const* value = as_integer(*limit); value != nullptr && *value >= 0)
            {
                target.limit = static_cast<std::size_t>(*value);
            }
        }
    }

    auto populate_room_filter(RoomFilter& target, canonicaljson::Object const& source) -> void
    {
        if (auto const* rooms = find_member(source, "rooms"); rooms != nullptr)
        {
            target.rooms = extract_strings(*rooms);
        }
        if (auto const* not_rooms = find_member(source, "not_rooms"); not_rooms != nullptr)
        {
            target.not_rooms = extract_strings(*not_rooms);
        }
        if (auto const* include_leave = find_member(source, "include_leave"); include_leave != nullptr)
        {
            if (auto const* value = as_boolean(*include_leave); value != nullptr)
            {
                target.include_leave = *value;
            }
        }
        if (auto const* timeline = find_member(source, "timeline"); timeline != nullptr)
        {
            if (auto const* obj = as_object(*timeline); obj != nullptr)
            {
                populate_event_filter(target.timeline, *obj);
            }
        }
        if (auto const* state = find_member(source, "state"); state != nullptr)
        {
            if (auto const* obj = as_object(*state); obj != nullptr)
            {
                populate_event_filter(target.state, *obj);
            }
        }
        if (auto const* ephemeral = find_member(source, "ephemeral"); ephemeral != nullptr)
        {
            if (auto const* obj = as_object(*ephemeral); obj != nullptr)
            {
                populate_event_filter(target.ephemeral, *obj);
            }
        }
        if (auto const* account_data = find_member(source, "account_data"); account_data != nullptr)
        {
            if (auto const* obj = as_object(*account_data); obj != nullptr)
            {
                populate_event_filter(target.account_data, *obj);
            }
        }
    }

} // namespace

auto parse_filter_argument(std::string_view filter_argument) -> SyncFilter
{
    auto out = SyncFilter{};
    if (filter_argument.empty())
    {
        return out;
    }
    // Treat a non-JSON token as a filter id reference. The alpha homeserver
    // does not yet persist named filters; without storage the safest behaviour
    // is "no filter" rather than rejecting the request, so the caller falls
    // back to default sync semantics. When filter storage lands the parser
    // can be extended to look up the stored JSON here.
    if (filter_argument.front() != '{')
    {
        return out;
    }
    auto const parsed = canonicaljson::parse_lossless(filter_argument);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return out;
    }
    auto const* root = as_object(parsed.value);
    if (root == nullptr)
    {
        return out;
    }
    if (auto const* room = find_member(*root, "room"); room != nullptr)
    {
        if (auto const* obj = as_object(*room); obj != nullptr)
        {
            populate_room_filter(out.room, *obj);
        }
    }
    if (auto const* presence = find_member(*root, "presence"); presence != nullptr)
    {
        if (auto const* obj = as_object(*presence); obj != nullptr)
        {
            populate_event_filter(out.presence, *obj);
        }
    }
    if (auto const* account_data = find_member(*root, "account_data"); account_data != nullptr)
    {
        if (auto const* obj = as_object(*account_data); obj != nullptr)
        {
            populate_event_filter(out.account_data, *obj);
        }
    }
    out.present = true;
    log_diagnostic("filter.parsed", {{"has_room_filter",    out.room.rooms.empty() ? "false" : "true",      false},
                                     {"has_presence_filter", out.presence.types.empty() ? "false" : "true", false}});
    return out;
}

auto event_passes_filter(EventTypeFilter const& filter, std::string_view event_type,
                         std::string_view sender) noexcept -> bool
{
    auto const contains = [](std::vector<std::string> const& list, std::string_view value) noexcept -> bool {
        return std::ranges::any_of(list, [value](std::string const& candidate) { return candidate == value; });
    };
    // Skip type predicates entirely when the caller hasn't supplied the
    // event type. The timeline walker currently passes an empty type for
    // stored PersistentEvent rows whose JSON we don't re-parse, and
    // applying types/not_types in that case would reject every event.
    if (!event_type.empty())
    {
        if (!filter.types.empty() && !contains(filter.types, event_type))
        {
            return false;
        }
        if (!filter.not_types.empty() && contains(filter.not_types, event_type))
        {
            return false;
        }
    }
    if (!filter.senders.empty() && !contains(filter.senders, sender))
    {
        return false;
    }
    if (!filter.not_senders.empty() && contains(filter.not_senders, sender))
    {
        return false;
    }
    return true;
}

auto room_passes_filter(RoomFilter const& filter, std::string_view room_id) noexcept -> bool
{
    auto const contains = [](std::vector<std::string> const& list, std::string_view value) noexcept -> bool {
        return std::ranges::any_of(list, [value](std::string const& candidate) { return candidate == value; });
    };
    if (!filter.rooms.empty() && !contains(filter.rooms, room_id))
    {
        return false;
    }
    if (!filter.not_rooms.empty() && contains(filter.not_rooms, room_id))
    {
        return false;
    }
    return true;
}

} // namespace merovingian::sync
