// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/CorrelationContext.hpp"

namespace merovingian::observability
{

class CorrelationScope final
{
public:
    explicit CorrelationScope(CorrelationContext const& context) noexcept;
    CorrelationScope(CorrelationScope const& other) = delete;
    auto operator=(CorrelationScope const& other) -> CorrelationScope& = delete;
    CorrelationScope(CorrelationScope&& other) = delete;
    auto operator=(CorrelationScope&& other) -> CorrelationScope& = delete;
    ~CorrelationScope();

private:
    CorrelationContext const* previous_{nullptr};
};

} // namespace merovingian::observability
