// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/PowerLevelEncoding.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::events
{

// One auth event read once, so that the auth rules look each field they need up in constant time instead of
// walking the event for every event they judge (ADR-0693). It borrows the event: the Value must outlive the index
// and must not change while it is used. Every lookup answers what the same lookup on the JSON answers: the first
// member with the key, and a power level decoded with the encoding the index was built with. An index built with
// no event stands for an absent auth event.
class IndexedAuthEvent final
{
public:
    // The levels of one power-level map of `content` (`users`, `events` or `notifications`).
    struct LevelMap final
    {
        // Whether `content` names the map as an object.
        bool present{false};
        // Each key's first entry, decoded; nullopt for a value that is not a power level in this encoding.
        std::unordered_map<std::string_view, std::optional<std::int64_t>> levels{};
        // Every decodable level, ascending, so a rule can count the entries at or above a level by a search.
        std::vector<std::int64_t> sorted_levels{};

        // The decoded level of `key`, or nullopt when the map does not name it or its value is not a level.
        [[nodiscard]] auto level(std::string_view key) const -> std::optional<std::int64_t>;
        // How many decodable levels are at least `threshold`, and how many are greater than it.
        [[nodiscard]] auto count_at_least(std::int64_t threshold) const noexcept -> std::size_t;
        [[nodiscard]] auto count_above(std::int64_t threshold) const noexcept -> std::size_t;
    };

    IndexedAuthEvent() noexcept = default;
    IndexedAuthEvent(canonicaljson::Value const& event, PowerLevelEncoding encoding);

    // The event, or a null Value for an absent one.
    [[nodiscard]] auto json() const noexcept -> canonicaljson::Value const&;
    // Whether there is an event: what `value_has_content` answers for the JSON.
    [[nodiscard]] auto present() const noexcept -> bool;
    [[nodiscard]] auto object() const noexcept -> canonicaljson::Object const*;
    [[nodiscard]] auto encoding() const noexcept -> PowerLevelEncoding;
    // The top-level `sender` and `state_key` when they are strings.
    [[nodiscard]] auto sender() const noexcept -> std::string const*;
    [[nodiscard]] auto state_key() const noexcept -> std::string const*;
    // `content` when it is an object, and one of its members.
    [[nodiscard]] auto content() const noexcept -> canonicaljson::Object const*;
    [[nodiscard]] auto content_member(std::string_view key) const -> canonicaljson::Value const*;
    [[nodiscard]] auto content_string(std::string_view key) const -> std::string const*;
    // A scalar power level of `content` (`users_default`, `events_default`, `state_default`, `ban`, `redact`,
    // `kick`, `invite`) decoded, or nullopt when absent or not a level. Any other key is decoded on demand.
    [[nodiscard]] auto power_level(std::string_view key) const -> std::optional<std::int64_t>;
    // `content.users`, `content.events` or `content.notifications`; an empty map for any other key.
    [[nodiscard]] auto level_map(std::string_view key) const noexcept -> LevelMap const&;
    // Whether `content.additional_creators` is an array holding the string `user_id`.
    [[nodiscard]] auto lists_additional_creator(std::string_view user_id) const -> bool;

private:
    canonicaljson::Value const* event_{nullptr};
    canonicaljson::Value null_{};
    PowerLevelEncoding encoding_{PowerLevelEncoding::integers};
    canonicaljson::Object const* object_{nullptr};
    std::string const* sender_{nullptr};
    std::string const* state_key_{nullptr};
    canonicaljson::Object const* content_{nullptr};
    std::unordered_map<std::string_view, canonicaljson::Value const*> content_members_{};
    std::unordered_map<std::string_view, std::optional<std::int64_t>> scalar_levels_{};
    LevelMap users_{};
    LevelMap events_{};
    LevelMap notifications_{};
    LevelMap no_map_{};
    std::unordered_set<std::string_view> additional_creators_{};
};

} // namespace merovingian::events
