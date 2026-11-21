// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace merovingian::tests
{

// Sets one logger module's level for the scope's lifetime, and restores what it was when the scope ends: an absent
// override stays absent rather than becoming a copy of the default. Changes process-wide logger state, so a scenario
// that uses it must not run in parallel with another in the same process (Catch2 runs scenarios one at a time).
class ModuleLogLevel final
{
public:
    ModuleLogLevel(std::string module, merovingian::observability::LogLevel level)
        : m_module{std::move(module)}
        , m_previous{merovingian::observability::SingleLog::instance().exchange_module_log_level(m_module, level)}
    {
    }
    ~ModuleLogLevel() noexcept
    {
        // Restoring an existing entry or erasing one allocates nothing, so this cannot throw.
        std::ignore = merovingian::observability::SingleLog::instance().exchange_module_log_level(m_module, m_previous);
    }
    ModuleLogLevel(ModuleLogLevel const&) = delete;
    auto operator=(ModuleLogLevel const&) -> ModuleLogLevel& = delete;
    ModuleLogLevel(ModuleLogLevel&&) = delete;
    auto operator=(ModuleLogLevel&&) -> ModuleLogLevel& = delete;

private:
    std::string m_module;
    std::optional<merovingian::observability::LogLevel> m_previous;
};

} // namespace merovingian::tests
