// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/edu_idempotence.hpp"

#include "merovingian/crypto/encoding.hpp"
#include "merovingian/crypto/generic_hash.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{
namespace
{

    constexpr auto max_message_id_codepoints = std::size_t{32U};

    // Length-prefixed so no (origin, sender, message_id) triple can collide with
    // another by shifting bytes across a separator.
    [[nodiscard]] auto window_key(std::string_view origin, std::string_view sender, std::string_view message_id)
        -> std::string
    {
        auto key = std::string{};
        for (auto const part : {origin, sender})
        {
            key.append(std::to_string(part.size()));
            key.push_back(':');
            key.append(part);
        }
        key.append(message_id);
        return key;
    }

    constexpr auto message_id_domain = std::string_view{"merovingian.m.direct_to_device.message_id"};
    // 18 bytes of digest encode to exactly 24 base64 characters with no padding.
    constexpr auto message_id_digest_bytes = std::size_t{18U};

} // namespace

auto EduIdempotenceWindow::seen(std::string_view origin, std::string_view sender, std::string_view message_id,
                                Clock::time_point now) const -> bool
{
    auto const found = keys_.find(window_key(origin, sender, message_id));
    return found != keys_.end() && now - found->second < lifetime_;
}

auto EduIdempotenceWindow::record(std::string_view origin, std::string_view sender, std::string_view message_id,
                                  Clock::time_point now) -> void
{
    // Expire from the front: entries are appended in time order.
    while (!order_.empty() && now - order_.front().seen_at >= lifetime_)
    {
        keys_.erase(order_.front().key);
        order_.pop_front();
    }

    auto key = window_key(origin, sender, message_id);
    if (keys_.contains(key) || capacity_ == 0U)
    {
        return;
    }
    while (order_.size() >= capacity_)
    {
        keys_.erase(order_.front().key);
        order_.pop_front();
    }
    keys_.emplace(key, now);
    order_.push_back(Entry{std::move(key), now});
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

auto derive_direct_to_device_message_id(std::string_view sender, std::string_view event_type, std::string_view txn_id)
    -> std::optional<std::string>
{
    // generic_hash_bytes separates its pieces with a NUL, which a transaction ID
    // can contain (a percent-encoded %00), so each input carries its own length
    // and the pieces cannot be re-split differently.
    auto const prefixed = [](std::string_view input) {
        return std::to_string(input.size()) + ":" + std::string{input};
    };
    auto const sender_piece = prefixed(sender);
    auto const type_piece = prefixed(event_type);
    auto const txn_piece = prefixed(txn_id);
    auto const pieces = std::array<std::string_view, 4U>{message_id_domain, sender_piece, type_piece, txn_piece};

    auto const digest = crypto::generic_hash_bytes(pieces);
    if (!digest.has_value() || digest->size() < message_id_digest_bytes)
    {
        return std::nullopt;
    }
    auto const raw = std::string_view{reinterpret_cast<char const*>(digest->data()), message_id_digest_bytes};
    return crypto::base64_urlsafe_encode(raw);
}

} // namespace merovingian::federation
