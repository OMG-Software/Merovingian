// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// MSC4186 §lists[*].ranges — a half-inclusive window [start, end].
struct SlidingSyncRange final
{
    std::uint64_t start{0U};
    std::uint64_t end{0U};

    [[nodiscard]] auto operator==(SlidingSyncRange const&) const -> bool = default;
};

} // namespace merovingian::sync
