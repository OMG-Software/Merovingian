// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>

namespace merovingian::tests
{

// Sends the console log to a string for the scope's lifetime. Safe only while
// the logger's asynchronous writer threads are not running, which is the case
// in the unit test binary.
class ConsoleLogCapture final
{
public:
    ConsoleLogCapture()
        : logger_{merovingian::observability::SingleLog::instance()}
    {
        REQUIRE_FALSE(logger_.get().writers_started());
        previous_level_ = logger_.get().exchange_console_log_level(merovingian::observability::LogLevel::info);
        previous_buffer_ = std::cout.rdbuf(output_.rdbuf());
    }
    ~ConsoleLogCapture()
    {
        std::cout.rdbuf(previous_buffer_);
        std::ignore = logger_.get().exchange_console_log_level(previous_level_);
    }
    ConsoleLogCapture(ConsoleLogCapture const&) = delete;
    auto operator=(ConsoleLogCapture const&) -> ConsoleLogCapture& = delete;
    ConsoleLogCapture(ConsoleLogCapture&&) = delete;
    auto operator=(ConsoleLogCapture&&) -> ConsoleLogCapture& = delete;

    // True when a line at `level` (the logger's name for it, such as "ERROR" or "CRITICAL") names `event`.
    [[nodiscard]] auto has_line(std::string_view level, std::string_view event) const -> bool
    {
        auto const tag = "<" + std::string{level} + ">";
        auto lines = std::istringstream{output_.str()};
        for (auto line = std::string{}; std::getline(lines, line);)
        {
            if (line.find(tag) != std::string::npos && line.find(event) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

private:
    std::reference_wrapper<merovingian::observability::SingleLog> logger_;
    std::ostringstream output_{};
    std::streambuf* previous_buffer_{nullptr};
    merovingian::observability::LogLevel previous_level_{};
};

} // namespace merovingian::tests
