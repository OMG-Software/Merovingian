// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

struct FederationQueryConfig final
{
    std::uint32_t max_backfill_pdus{500U};
    std::uint32_t max_missing_events_pdus{100U};
    std::uint32_t max_missing_events_latest{100U};
    std::uint32_t max_missing_events_traversal{4096U};
};

} // namespace merovingian::config
