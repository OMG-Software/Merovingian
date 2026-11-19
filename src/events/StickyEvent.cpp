// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/StickyEvent.hpp"

#include "merovingian/canonicaljson/ObjectMember.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace merovingian::events
{

namespace
{

    constexpr auto duration_key = std::string_view{"duration_ms"};
    constexpr auto state_key_field = std::string_view{"state_key"};

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

    // The `duration_ms` of a sticky object. nullopt for anything but an object holding an integer of at least 1.
    [[nodiscard]] auto duration_of_object(canonicaljson::Value const& value) -> std::optional<std::int64_t>
    {
        auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* duration = find_member(*object, duration_key);
        if (duration == nullptr)
        {
            return std::nullopt;
        }
        // A float or an out-of-range integer is a double or a RawNumber, never an int64, so it is refused here.
        auto const* integer = std::get_if<std::int64_t>(&duration->storage());
        if (integer == nullptr || *integer < 1)
        {
            return std::nullopt;
        }
        return *integer;
    }

    [[nodiscard]] auto saturating_add(std::int64_t left, std::int64_t right) noexcept -> std::int64_t
    {
        constexpr auto lowest = std::numeric_limits<std::int64_t>::min();
        constexpr auto highest = std::numeric_limits<std::int64_t>::max();
        if (right > 0 && left > highest - right)
        {
            return highest;
        }
        if (right < 0 && left < lowest - right)
        {
            return lowest;
        }
        return left + right;
    }

} // namespace

auto sticky_duration_of(canonicaljson::Value const& pdu) -> std::optional<std::int64_t>
{
    auto const* object = std::get_if<canonicaljson::Object>(&pdu.storage());
    if (object == nullptr || find_member(*object, state_key_field) != nullptr)
    {
        return std::nullopt;
    }
    auto const* stable = find_member(*object, sticky_field);
    auto const* unstable = find_member(*object, unstable_sticky_field);
    auto stable_duration = std::optional<std::int64_t>{};
    auto unstable_duration = std::optional<std::int64_t>{};
    if (stable != nullptr)
    {
        stable_duration = duration_of_object(*stable);
        if (!stable_duration.has_value())
        {
            return std::nullopt;
        }
    }
    if (unstable != nullptr)
    {
        unstable_duration = duration_of_object(*unstable);
        if (!unstable_duration.has_value())
        {
            return std::nullopt;
        }
    }
    if (stable_duration.has_value() && unstable_duration.has_value() && *stable_duration != *unstable_duration)
    {
        return std::nullopt;
    }
    return stable_duration.has_value() ? stable_duration : unstable_duration;
}

auto parse_sticky_duration_text(std::string_view text) -> std::optional<std::int64_t>
{
    if (text.empty() || !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; }))
    {
        return std::nullopt;
    }
    auto parsed = std::int64_t{0};
    auto const [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (error != std::errc{} || end != text.data() + text.size() || parsed < 1)
    {
        return std::nullopt;
    }
    return parsed;
}

auto sticky_expiry_ms(std::int64_t origin_server_ts, std::int64_t received_at_ms, std::int64_t duration_ms) noexcept
    -> std::int64_t
{
    return saturating_add(std::min(received_at_ms, origin_server_ts), std::min(duration_ms, max_sticky_duration_ms));
}

auto sticky_remaining_ms(std::int64_t expires_at_ms, std::int64_t now_ms) noexcept -> std::optional<std::int64_t>
{
    constexpr auto highest = std::numeric_limits<std::int64_t>::max();
    constexpr auto lowest = std::numeric_limits<std::int64_t>::min();
    auto remaining = std::int64_t{0};
    if (now_ms < 0 && expires_at_ms > highest + now_ms)
    {
        remaining = highest;
    }
    else if (now_ms > 0 && expires_at_ms < lowest + now_ms)
    {
        return std::nullopt;
    }
    else
    {
        remaining = expires_at_ms - now_ms;
    }
    if (remaining <= 0)
    {
        return std::nullopt;
    }
    return remaining;
}

auto sticky_object(std::int64_t duration_ms) -> canonicaljson::Value
{
    auto members = canonicaljson::Object{};
    members.push_back(canonicaljson::make_member(std::string{duration_key}, canonicaljson::Value{duration_ms}));
    return canonicaljson::Value{std::move(members)};
}

} // namespace merovingian::events
