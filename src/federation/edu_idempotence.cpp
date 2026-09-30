// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/edu_idempotence.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{
namespace
{

    constexpr auto max_message_id_codepoints = std::size_t{32U};

    // Length-prefixed so no (origin, message_id) pair can collide with another
    // by shifting bytes across the separator.
    [[nodiscard]] auto window_key(std::string_view origin, std::string_view message_id) -> std::string
    {
        auto key = std::to_string(origin.size());
        key.push_back(':');
        key.append(origin);
        key.append(message_id);
        return key;
    }

} // namespace

auto EduIdempotenceWindow::first_sighting(std::string_view origin, std::string_view message_id,
                                          Clock::time_point now) -> bool
{
    // Expire from the front: entries are appended in time order.
    while (!order_.empty() && now - order_.front().seen_at >= lifetime_)
    {
        keys_.erase(order_.front().key);
        order_.pop_front();
    }

    auto key = window_key(origin, message_id);
    if (keys_.contains(key))
    {
        return false;
    }
    if (capacity_ == 0U)
    {
        return true;
    }
    while (order_.size() >= capacity_)
    {
        keys_.erase(order_.front().key);
        order_.pop_front();
    }
    keys_.insert(key);
    order_.push_back(Entry{std::move(key), now});
    return true;
}

auto direct_to_device_message_id_is_valid(std::string_view message_id) noexcept -> bool
{
    if (message_id.empty())
    {
        return false;
    }
    // Count codepoints as the bytes that are not UTF-8 continuation bytes.
    auto const codepoints = static_cast<std::size_t>(std::ranges::count_if(message_id, [](char byte) {
        return (static_cast<unsigned char>(byte) & 0xC0U) != 0x80U;
    }));
    return codepoints <= max_message_id_codepoints;
}

} // namespace merovingian::federation
