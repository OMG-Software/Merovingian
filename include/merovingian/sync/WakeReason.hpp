// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// Why a parked long-poll is being resumed (ADR-0569).
enum class WakeReason : std::uint8_t
{
    // A publish concerned its user (or was a broadcast): rerun it.
    published,
    // Its deadline passed: make the final rerun and answer.
    deadline,
};

} // namespace merovingian::sync
