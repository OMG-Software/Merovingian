// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/LogLevel.hpp"

#include <string>
#include <unordered_map>

namespace merovingian::config
{

// Per-module log level overrides. Populated from `log_modules.<name>=<level>`
// keys in `merovingian.conf`. The wildcard key `*` sets the default for
// modules without an explicit entry (equivalent to
// `SingleLog::set_default_log_level`). Hot-reload is deliberately not
// supported in 0.5.0: log_modules affects startup-time bootstrap only
// and restart is required.
struct LogModulesConfig final
{
    std::unordered_map<std::string, observability::LogLevel> levels{};
};

} // namespace merovingian::config
