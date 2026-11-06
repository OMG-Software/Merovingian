// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/CorrelationScope.hpp"

#include "merovingian/observability/observability_internal.hpp"

#include <utility>

namespace merovingian::observability
{

CorrelationScope::CorrelationScope(CorrelationContext context) noexcept
    : context_{std::move(context)}
    , previous_{detail::correlation_slot()}
{
    detail::correlation_slot() = &context_;
}

CorrelationScope::~CorrelationScope()
{
    detail::correlation_slot() = previous_;
}

} // namespace merovingian::observability
