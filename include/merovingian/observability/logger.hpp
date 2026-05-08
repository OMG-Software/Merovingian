// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::observability {

enum class LogLevel {
    trace,
    debug,
    info,
    warning,
    error,
    critical,
};

class Logger final {
public:
    Logger() = default;

    auto log(LogLevel level, std::string_view message) -> void;
};

} // namespace merovingian::observability
