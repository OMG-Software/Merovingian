// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SlidingSyncPosBinding.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/GenericHash.hpp"

#include <array>
#include <string>

namespace merovingian::homeserver
{

namespace
{
    constexpr auto mac_separator = '-';

    // The label keeps this MAC apart from every other use of the deployment's pagination token key (ADR-0866): no
    // other input to that key starts with it.
    constexpr auto mac_label = std::string_view{"merovingian.sliding_sync.pos.v1"};

    [[nodiscard]] auto mac_for(std::string_view pos, std::string_view user_id, std::string_view device_id,
                               std::span<std::uint8_t const> key) -> std::optional<std::string>
    {
        if (key.empty())
        {
            return std::nullopt;
        }
        auto const pieces = std::array<std::string_view, 4U>{mac_label, user_id, device_id, pos};
        return crypto::generic_hash(pieces, key);
    }
} // namespace

auto bind_sliding_sync_pos(std::string_view pos, std::string_view user_id, std::string_view device_id,
                           std::span<std::uint8_t const> key) -> std::optional<std::string>
{
    auto const mac = mac_for(pos, user_id, device_id, key);
    if (!mac.has_value())
    {
        return std::nullopt;
    }
    auto bound = std::string{pos};
    bound += mac_separator;
    bound += *mac;
    return bound;
}

auto unbind_sliding_sync_pos(std::string_view bound, std::string_view user_id, std::string_view device_id,
                             std::span<std::uint8_t const> key) -> std::optional<std::string_view>
{
    auto const separator = bound.rfind(mac_separator);
    if (separator == std::string_view::npos || separator == 0U)
    {
        return std::nullopt;
    }
    auto const pos = bound.substr(0U, separator);
    auto const mac = mac_for(pos, user_id, device_id, key);
    if (!mac.has_value() || !crypto::constant_time_equal_variable_length(*mac, bound.substr(separator + 1U)))
    {
        return std::nullopt;
    }
    return pos;
}

} // namespace merovingian::homeserver
