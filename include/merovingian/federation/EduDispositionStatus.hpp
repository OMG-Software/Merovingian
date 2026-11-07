// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

enum class EduDispositionStatus : std::uint8_t
{
    accepted,
    rejected_invalid,
    dropped_unknown_type,
};

} // namespace merovingian::federation
