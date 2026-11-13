// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/IndexedAuthEvent.hpp"

#include "merovingian/events/Authorization.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::events
{

namespace
{

    constexpr auto scalar_keys = std::array{
        std::string_view{"users_default"}, std::string_view{"events_default"}, std::string_view{"state_default"},
        std::string_view{"ban"},           std::string_view{"redact"},         std::string_view{"kick"},
        std::string_view{"invite"},
    };

    // The first member of `object` named `key`, as the auth rules' own lookup finds it.
    [[nodiscard]] auto first_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        auto const found = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return found == object.end() ? nullptr : found->value.get();
    }

    [[nodiscard]] auto decode(canonicaljson::Value const* value, PowerLevelEncoding encoding)
        -> std::optional<std::int64_t>
    {
        return value == nullptr ? std::nullopt : decode_power_level(*value, encoding);
    }

    auto index_level_map(IndexedAuthEvent::LevelMap& map, canonicaljson::Value const* value,
                         PowerLevelEncoding encoding) -> void
    {
        auto const* entries = value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
        if (entries == nullptr)
        {
            return;
        }
        map.present = true;
        map.levels.reserve(entries->size());
        for (auto const& entry : *entries)
        {
            map.levels.emplace(entry.key, decode(entry.value.get(), encoding));
        }
        map.sorted_levels.reserve(map.levels.size());
        for (auto const& [key, level] : map.levels)
        {
            if (level.has_value())
            {
                map.sorted_levels.push_back(*level);
            }
        }
        std::ranges::sort(map.sorted_levels);
    }

} // namespace

auto IndexedAuthEvent::LevelMap::level(std::string_view key) const -> std::optional<std::int64_t>
{
    auto const found = levels.find(key);
    return found == levels.end() ? std::nullopt : found->second;
}

auto IndexedAuthEvent::LevelMap::count_at_least(std::int64_t threshold) const noexcept -> std::size_t
{
    auto const first = std::ranges::lower_bound(sorted_levels, threshold);
    return static_cast<std::size_t>(std::distance(first, sorted_levels.end()));
}

auto IndexedAuthEvent::LevelMap::count_above(std::int64_t threshold) const noexcept -> std::size_t
{
    auto const first = std::ranges::upper_bound(sorted_levels, threshold);
    return static_cast<std::size_t>(std::distance(first, sorted_levels.end()));
}

IndexedAuthEvent::IndexedAuthEvent(canonicaljson::Value const& event, PowerLevelEncoding encoding)
    : event_{&event}
    , encoding_{encoding}
    , object_{std::get_if<canonicaljson::Object>(&event.storage())}
{
    if (object_ == nullptr)
    {
        return;
    }
    if (auto const* sender = first_member(*object_, "sender"); sender != nullptr)
    {
        sender_ = std::get_if<std::string>(&sender->storage());
    }
    if (auto const* state_key = first_member(*object_, "state_key"); state_key != nullptr)
    {
        state_key_ = std::get_if<std::string>(&state_key->storage());
    }
    if (auto const* content = first_member(*object_, "content"); content != nullptr)
    {
        content_ = std::get_if<canonicaljson::Object>(&content->storage());
    }
    if (content_ == nullptr)
    {
        return;
    }
    content_members_.reserve(content_->size());
    for (auto const& member : *content_)
    {
        content_members_.emplace(member.key, member.value.get());
    }
    for (auto const key : scalar_keys)
    {
        scalar_levels_.emplace(key, decode(content_member(key), encoding));
    }
    index_level_map(users_, content_member("users"), encoding);
    index_level_map(events_, content_member("events"), encoding);
    index_level_map(notifications_, content_member("notifications"), encoding);
    if (auto const* creators = content_member("additional_creators"); creators != nullptr)
    {
        if (auto const* array = std::get_if<canonicaljson::Array>(&creators->storage()); array != nullptr)
        {
            for (auto const& element : *array)
            {
                if (auto const* user_id = std::get_if<std::string>(&element.storage()); user_id != nullptr)
                {
                    additional_creators_.emplace(*user_id);
                }
            }
        }
    }
}

auto IndexedAuthEvent::json() const noexcept -> canonicaljson::Value const&
{
    return event_ == nullptr ? null_ : *event_;
}

auto IndexedAuthEvent::present() const noexcept -> bool
{
    return !std::holds_alternative<std::nullptr_t>(json().storage());
}

auto IndexedAuthEvent::object() const noexcept -> canonicaljson::Object const*
{
    return object_;
}

auto IndexedAuthEvent::encoding() const noexcept -> PowerLevelEncoding
{
    return encoding_;
}

auto IndexedAuthEvent::sender() const noexcept -> std::string const*
{
    return sender_;
}

auto IndexedAuthEvent::state_key() const noexcept -> std::string const*
{
    return state_key_;
}

auto IndexedAuthEvent::content() const noexcept -> canonicaljson::Object const*
{
    return content_;
}

auto IndexedAuthEvent::content_member(std::string_view key) const -> canonicaljson::Value const*
{
    auto const found = content_members_.find(key);
    return found == content_members_.end() ? nullptr : found->second;
}

auto IndexedAuthEvent::content_string(std::string_view key) const -> std::string const*
{
    auto const* value = content_member(key);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

auto IndexedAuthEvent::power_level(std::string_view key) const -> std::optional<std::int64_t>
{
    if (auto const found = scalar_levels_.find(key); found != scalar_levels_.end())
    {
        return found->second;
    }
    return decode(content_member(key), encoding_);
}

auto IndexedAuthEvent::level_map(std::string_view key) const noexcept -> LevelMap const&
{
    if (key == "users")
    {
        return users_;
    }
    if (key == "events")
    {
        return events_;
    }
    if (key == "notifications")
    {
        return notifications_;
    }
    return no_map_;
}

auto IndexedAuthEvent::lists_additional_creator(std::string_view user_id) const -> bool
{
    return additional_creators_.contains(user_id);
}

} // namespace merovingian::events
