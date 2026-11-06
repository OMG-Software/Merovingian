// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/CorrelationContext.hpp"

namespace merovingian::observability
{

// Publishes a correlation context on the calling thread for the scope's lifetime, then restores the previous one.
// The scope owns its copy of the context and publishes a pointer to that copy, so what readers see cannot change or
// dangle while the scope is open, whatever happens to the caller's object (CodeQL cpp/stack-address-escape).
class CorrelationScope final
{
public:
    explicit CorrelationScope(CorrelationContext context) noexcept;
    CorrelationScope(CorrelationScope const& other) = delete;
    auto operator=(CorrelationScope const& other) -> CorrelationScope& = delete;
    CorrelationScope(CorrelationScope&& other) = delete;
    auto operator=(CorrelationScope&& other) -> CorrelationScope& = delete;
    ~CorrelationScope();

private:
    CorrelationContext context_;
    CorrelationContext const* previous_{nullptr};
};

} // namespace merovingian::observability
