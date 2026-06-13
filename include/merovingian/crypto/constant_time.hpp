// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::crypto
{

[[nodiscard]] auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool;

} // namespace merovingian::crypto
