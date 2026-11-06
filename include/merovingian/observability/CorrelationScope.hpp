// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/CorrelationContext.hpp"

#include <optional>

namespace merovingian::observability
{

// Publishes a correlation context on the calling thread for the scope's lifetime, then restores the previous one.
// The thread's slot holds the context by value: the scope moves its context in and keeps the one it displaced, and
// nothing stores the address of a scope or of a caller's object, both of which live on the stack (ADR-0526, CodeQL
// cpp/stack-address-escape). What readers see cannot change or dangle while the scope is open.
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
    // The context this scope displaced, put back when it closes.
    std::optional<CorrelationContext> previous_{};
};

} // namespace merovingian::observability
