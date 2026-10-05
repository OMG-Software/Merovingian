// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-9 (2026-09-29 security audit): control characters in logged values must
// not forge extra log lines or reach the operator's terminal raw. Asserted at
// the real synchronous console sink rather than at a formatting helper.

#include "merovingian/observability/logger.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::observability::diagnostic_message;
using merovingian::observability::LogLevel;
using merovingian::observability::SingleLog;
using merovingian::observability::StructuredLogField;

class ConsoleCapture final
{
public:
    ConsoleCapture()
        : m_previous{std::cout.rdbuf(m_buffer.rdbuf())}
    {
    }

    ~ConsoleCapture()
    {
        std::cout.rdbuf(m_previous);
    }

    ConsoleCapture(ConsoleCapture const&) = delete;
    auto operator=(ConsoleCapture const&) -> ConsoleCapture& = delete;
    ConsoleCapture(ConsoleCapture&&) = delete;
    auto operator=(ConsoleCapture&&) -> ConsoleCapture& = delete;

    [[nodiscard]] auto text() const -> std::string
    {
        return m_buffer.str();
    }

private:
    std::ostringstream m_buffer{};
    std::streambuf* m_previous{nullptr};
};

[[nodiscard]] auto physical_line_count(std::string_view text) -> std::size_t
{
    return static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
}

} // namespace

SCENARIO("Structured log controls are escaped at the real console sink",
         "[observability][logger][security][log_controls]")
{
    GIVEN("a local logger writing synchronously to a captured console")
    {
        auto capture = ConsoleCapture{};
        auto logger = SingleLog{};
        logger.set_console_log_level(LogLevel::trace);
        logger.set_file_log_level(LogLevel::off);
        logger.set_default_log_level(LogLevel::trace);

        WHEN("structured values, keys, and event names contain control bytes")
        {
            auto controls = std::string{"line"};
            controls.push_back('\n');
            controls += "return";
            controls.push_back('\r');
            controls += "tab";
            controls.push_back('\t');
            controls += "nul";
            controls.push_back('\0');
            controls += "escape";
            controls.push_back('\x1b');
            controls += "delete";
            controls.push_back('\x7f');
            controls += "雪🙂";

            logger.warning("auth",
                           diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                    {"user_id",      controls,                    false},
                                                                    {"access_token", "never-log-this-secret",     true },
                                                                    {"password",     "second-secret-is-redacted", false},
            }));
            logger.warning("auth", diagnostic_message("login\nforged", std::vector<StructuredLogField>{
                                                                           {"server\nname", "example.org", false},
            }));

            THEN("each call is one physical record with printable controls and preserved redaction")
            {
                auto const output = capture.text();
                CHECK(physical_line_count(output) == 2U);
                CHECK(output.find("line\\nreturn\\rtab\\tnul\\x00escape\\x1bdelete\\x7f雪🙂") != std::string::npos);
                CHECK(output.find("event=login\\nforged") != std::string::npos);
                CHECK(output.find("server\\nname=example.org") != std::string::npos);
                CHECK(output.find("never-log-this-secret") == std::string::npos);
                CHECK(output.find("second-secret-is-redacted") == std::string::npos);
                CHECK(output.find("access_token=<redacted>") != std::string::npos);
                CHECK(output.find("password=<redacted>") != std::string::npos);
            }
        }
    }
}

SCENARIO("C1 control characters are escaped at the real console sink",
         "[observability][logger][security][log_controls]")
{
    GIVEN("a local logger writing synchronously to a captured console")
    {
        auto capture = ConsoleCapture{};
        auto logger = SingleLog{};
        logger.set_console_log_level(LogLevel::trace);
        logger.set_file_log_level(LogLevel::off);
        logger.set_default_log_level(LogLevel::trace);

        WHEN("a value contains UTF-8 encoded C1 controls, including the single-character CSI introducer")
        {
            // U+0085 NEXT LINE and U+009B CONTROL SEQUENCE INTRODUCER, then
            // U+00A0 NO-BREAK SPACE, the first printable code point after the
            // C1 block. Literals are split so each \x escape ends where intended.
            auto const value = std::string{"a\xc2\x85"} + "b\xc2\x9b" + "31mc\xc2\xa0" + "d";
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("the C1 controls are printable escapes and the printable code point is kept")
            {
                auto const output = capture.text();
                CHECK(physical_line_count(output) == 1U);
                CHECK(output.find(std::string{"user_id=a\\u0085b\\u009b31mc\xc2\xa0"} + "d") != std::string::npos);
                CHECK(output.find("\xc2\x85") == std::string::npos);
                CHECK(output.find("\xc2\x9b") == std::string::npos);
            }
        }
    }
}
