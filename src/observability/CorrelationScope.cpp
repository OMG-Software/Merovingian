// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/CorrelationScope.hpp"

#include "merovingian/observability/ObservabilityInternal.hpp"

#include <optional>
#include <utility>

namespace merovingian::observability
{

CorrelationScope::CorrelationScope(CorrelationContext context) noexcept
    : previous_{std::exchange(detail::correlation_slot(), std::optional<CorrelationContext>{std::move(context)})}
{
}

CorrelationScope::~CorrelationScope()
{
    detail::correlation_slot() = std::move(previous_);
}

} // namespace merovingian::observability
