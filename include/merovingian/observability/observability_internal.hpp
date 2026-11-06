// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/CorrelationContext.hpp"

namespace merovingian::observability::detail
{

// The calling thread's current correlation context, shared by current_correlation_context() and
// CorrelationScope. Module-internal: not public API.
auto correlation_slot() noexcept -> CorrelationContext const*&;

} // namespace merovingian::observability::detail
