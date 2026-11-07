// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::observability
{

struct AuditRateDecision final
{
    // False when the event must not be written durably; it has been counted.
    bool write{true};
    // Number of events the kind suppressed since its last written row. Non-zero
    // only on the first row written after a window that overran its allowance.
    std::uint64_t suppressed{0U};
};

} // namespace merovingian::observability
