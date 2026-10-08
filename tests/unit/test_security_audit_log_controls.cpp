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

namespace
{

using merovingian::observability::max_log_field_value_bytes;

// The text a single-field diagnostic wrote after "key=", up to the record's own
// line terminator. Values in these scenarios contain no space, so nothing else
// can follow the value on the line.
[[nodiscard]] auto emitted_field_value(std::string_view output, std::string_view key) -> std::string
{
    auto const needle = std::string{" "} + std::string{key} + "=";
    auto const start = output.find(needle);
    if (start == std::string_view::npos)
    {
        return {};
    }
    auto const value_start = start + needle.size();
    auto const end = output.find('\n', value_start);
    return std::string{
        output.substr(value_start, end == std::string_view::npos ? std::string_view::npos : end - value_start)};
}

[[nodiscard]] auto truncation_marker(std::size_t dropped) -> std::string
{
    return "...[truncated " + std::to_string(dropped) + " bytes]";
}

// Structural UTF-8 validity: every lead byte is followed by its continuation
// bytes, and no stray continuation byte appears.
[[nodiscard]] auto is_well_formed_utf8(std::string_view text) -> bool
{
    auto index = std::size_t{0U};
    while (index < text.size())
    {
        auto const byte = static_cast<unsigned char>(text[index]);
        auto length = std::size_t{1U};
        if (byte >= 0xf0U && byte <= 0xf4U)
        {
            length = 4U;
        }
        else if (byte >= 0xe0U && byte <= 0xefU)
        {
            length = 3U;
        }
        else if (byte >= 0xc2U && byte <= 0xdfU)
        {
            length = 2U;
        }
        else if (byte >= 0x80U)
        {
            return false;
        }
        if (index + length > text.size())
        {
            return false;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            if ((static_cast<unsigned char>(text[index + offset]) & 0xc0U) != 0x80U)
            {
                return false;
            }
        }
        index += length;
    }
    return true;
}

[[nodiscard]] auto repeated(std::string_view unit, std::size_t count) -> std::string
{
    auto result = std::string{};
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        result.append(unit);
    }
    return result;
}

} // namespace

SCENARIO("A structured log field value is capped at the real console sink",
         "[observability][logger][security][log_controls][auth-9]")
{
    GIVEN("a local logger writing synchronously to a captured console")
    {
        auto capture = ConsoleCapture{};
        auto logger = SingleLog{};
        logger.set_console_log_level(LogLevel::trace);
        logger.set_file_log_level(LogLevel::off);
        logger.set_default_log_level(LogLevel::trace);

        WHEN("a field value is one mebibyte")
        {
            auto const size = std::size_t{1024U * 1024U};
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", std::string(size, 'a'), false},
            }));

            THEN("the value is cut to the cap plus a marker naming the dropped "
                 "bytes, on one physical line")
            {
                auto const output = capture.text();
                CHECK(physical_line_count(output) == 1U);
                auto const value = emitted_field_value(output, "user_id");
                CHECK(value == std::string(max_log_field_value_bytes, 'a') +
                                   truncation_marker(size - max_log_field_value_bytes));
                CHECK(output.size() < max_log_field_value_bytes + 256U);
            }
        }

        WHEN("a field value is exactly the cap")
        {
            auto const value = std::string(max_log_field_value_bytes, 'b');
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("it is emitted unchanged")
            {
                CHECK(emitted_field_value(capture.text(), "user_id") == value);
            }
        }

        WHEN("a field value is one byte over the cap")
        {
            auto const value = std::string(max_log_field_value_bytes + 1U, 'c');
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("the last byte is dropped and the marker says one byte was")
            {
                CHECK(emitted_field_value(capture.text(), "user_id") ==
                      std::string(max_log_field_value_bytes, 'c') + truncation_marker(1U));
            }
        }

        WHEN("the cap falls inside a multi-byte UTF-8 character")
        {
            // One ASCII byte then three-byte characters: the cap lands one byte
            // into a character, so the whole last character must be dropped.
            auto const value = std::string{"x"} + repeated("\xe4\xbb\xaa", (max_log_field_value_bytes / 3U) + 20U);
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("the emitted value is well-formed UTF-8, within the cap, and the "
                 "marker counts the dropped bytes")
            {
                auto const emitted = emitted_field_value(capture.text(), "user_id");
                auto const marker_at = emitted.find("...[truncated ");
                REQUIRE(marker_at != std::string::npos);
                auto const kept = emitted.substr(0U, marker_at);
                CHECK(kept.size() <= max_log_field_value_bytes);
                CHECK(kept.size() > max_log_field_value_bytes - 3U);
                CHECK(is_well_formed_utf8(emitted));
                CHECK(emitted.substr(marker_at) == truncation_marker(value.size() - kept.size()));
            }
        }

        WHEN("a long value is full of control characters")
        {
            auto const value = std::string(100000U, '\n');
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("it is escaped, and the escaped output is within the cap")
            {
                auto const output = capture.text();
                CHECK(physical_line_count(output) == 1U);
                auto const emitted = emitted_field_value(output, "user_id");
                auto const marker_at = emitted.find("...[truncated ");
                REQUIRE(marker_at != std::string::npos);
                CHECK(emitted.substr(0U, marker_at) == repeated("\\n", max_log_field_value_bytes / 2U));
                CHECK(emitted.substr(marker_at) == truncation_marker(value.size() - (max_log_field_value_bytes / 2U)));
            }
        }

        WHEN("a four-byte control escape would straddle the cap")
        {
            auto const value = std::string(max_log_field_value_bytes - 2U, 'a') + std::string(100U, '\x01');
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", value, false},
            }));

            THEN("the escape is dropped whole, never cut in half")
            {
                auto const emitted = emitted_field_value(capture.text(), "user_id");
                auto const marker_at = emitted.find("...[truncated ");
                REQUIRE(marker_at != std::string::npos);
                CHECK(emitted.substr(0U, marker_at) == std::string(max_log_field_value_bytes - 2U, 'a'));
            }
        }

        WHEN("a sensitive field carries a huge value")
        {
            auto const value = std::string(100000U, 'p');
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"password", value, false},
            }));

            THEN("it is still redacted and no part of it appears")
            {
                auto const output = capture.text();
                CHECK(emitted_field_value(output, "password") == "<redacted>");
                CHECK(output.find("pppp") == std::string::npos);
            }
        }

        WHEN("an ordinary short value is logged")
        {
            logger.warning("auth", diagnostic_message("login.rejected", std::vector<StructuredLogField>{
                                                                            {"user_id", "@alice:example.org", false},
            }));

            THEN("it is emitted unchanged with no marker")
            {
                CHECK(emitted_field_value(capture.text(), "user_id") == "@alice:example.org");
            }
        }
    }
}

SCENARIO("A structured log summary caps field values the same way", "[observability][security][auth-9]")
{
    GIVEN("a structured field with an oversized value")
    {
        auto const value = std::string(10000U, 'z');

        WHEN("the structured summary is built")
        {
            auto const summary = merovingian::observability::diagnostic_log_summary("auth", "login.rejected",
                                                                                    std::vector<StructuredLogField>{
                                                                                        {"user_id", value, false}
            });

            THEN("the value is capped with the marker")
            {
                CHECK(summary.find(std::string(max_log_field_value_bytes, 'z') +
                                   truncation_marker(value.size() - max_log_field_value_bytes)) != std::string::npos);
                CHECK(summary.size() < max_log_field_value_bytes + 256U);
            }
        }
    }
}
