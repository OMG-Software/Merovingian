// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>

namespace merovingian::auth
{

// Fixed-size identity of a counted subject: an unkeyed BLAKE2b-256 digest of the
// subject kind and its parts. Fixed size means a client-chosen 60 KiB user ID
// costs the same as a short one. Unkeyed is enough: the table lives in process
// memory, and a 256-bit collision-resistant digest means a client cannot choose
// a name that lands on somebody else's counter.
struct FailureKey final
{
    std::array<std::uint8_t, 32U> digest{};

    [[nodiscard]] friend auto operator==(FailureKey const&, FailureKey const&) noexcept -> bool = default;
};

} // namespace merovingian::auth
