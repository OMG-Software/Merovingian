// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/CorrelationContext.hpp"

#include <optional>

namespace merovingian::observability::detail
{

// The calling thread's current correlation context, held by value, shared by current_correlation_context() and
// CorrelationScope. Module-internal: not public API. Never make it hold a pointer: what it would point at is a scope or
// a caller's object on the stack (ADR-0526).
auto correlation_slot() noexcept -> std::optional<CorrelationContext>&;

} // namespace merovingian::observability::detail
