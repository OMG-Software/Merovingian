// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::sync
{

// The result of a park. A struct rather than std::expected, which this project's toolchain does not build. When
// `parked` is false the poll was not moved from and `refusal` says why.
struct ParkOutcome final
{
    bool parked{false};
    std::uint64_t ticket{0U};
    std::string refusal{};
};

} // namespace merovingian::sync
