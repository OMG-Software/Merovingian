// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-1 (security-audit-report-2026-09-29.md): every attacker-controlled audit
// field is bounded to `max_audit_field_bytes` before it is stored or logged.
// These scenarios pin the bounding helper on its own; test_audit_flood.cpp
// covers the wiring through the audit-append layer.

#include "merovingian/database/bounded_text.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

constexpr auto replacement = std::string_view{"\xEF\xBF\xBD"};

// Returns true when `text` is well-formed UTF-8 (no overlongs, surrogates or
// out-of-range code points). Independent of the helper under test.
[[nodiscard]] auto is_well_formed_utf8(std::string_view text) -> bool
{
    auto index = std::size_t{0U};
    while (index < text.size())
    {
        auto const first = static_cast<unsigned char>(text[index]);
        auto length = std::size_t{0U};
        auto codepoint = std::uint32_t{0U};
        auto minimum = std::uint32_t{0U};
        if (first < 0x80U)
        {
            ++index;
            continue;
        }
        if ((first & 0xE0U) == 0xC0U)
        {
            length = 2U;
            codepoint = first & 0x1FU;
            minimum = 0x80U;
        }
        else if ((first & 0xF0U) == 0xE0U)
        {
            length = 3U;
            codepoint = first & 0x0FU;
            minimum = 0x800U;
        }
        else if ((first & 0xF8U) == 0xF0U)
        {
            length = 4U;
            codepoint = first & 0x07U;
            minimum = 0x10000U;
        }
        else
        {
            return false;
        }
        if (index + length > text.size())
        {
            return false;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            auto const next = static_cast<unsigned char>(text[index + offset]);
            if ((next & 0xC0U) != 0x80U)
            {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        if (codepoint < minimum || codepoint > 0x10FFFFU || (codepoint >= 0xD800U && codepoint <= 0xDFFFU))
        {
            return false;
        }
        index += length;
    }
    return true;
}

} // namespace

SCENARIO("bounded_utf8 leaves short well-formed text untouched", "[database][audit][utf8]")
{
    GIVEN("a short ASCII string and a short multi-byte string")
    {
        auto const ascii = std::string{"@alice:example.org"};
        auto const multibyte = std::string{"caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x94\x92"};

        WHEN("each is bounded to 255 bytes")
        {
            auto const bounded_ascii = merovingian::database::bounded_utf8(ascii, 255U);
            auto const bounded_multibyte = merovingian::database::bounded_utf8(multibyte, 255U);

            THEN("the text is unchanged")
            {
                REQUIRE(bounded_ascii == ascii);
                REQUIRE(bounded_multibyte == multibyte);
            }
        }
    }
}

SCENARIO("bounded_utf8 never exceeds the byte limit and never splits a multi-byte sequence", "[database][audit][utf8]")
{
    GIVEN("a 60 KiB string of ASCII and a string of 3-byte characters whose boundary straddles the limit")
    {
        auto const ascii = std::string(60U * 1024U, 'a');
        auto euro = std::string{};
        for (auto i = 0; i < 200; ++i)
        {
            euro += "\xE2\x82\xAC"; // U+20AC, 3 bytes: 600 bytes total
        }

        WHEN("each is bounded to 255 bytes")
        {
            auto const bounded_ascii = merovingian::database::bounded_utf8(ascii, 255U);
            auto const bounded_euro = merovingian::database::bounded_utf8(euro, 255U);

            THEN("both fit, and the multi-byte string was cut on a character boundary")
            {
                REQUIRE(bounded_ascii.size() == 255U);
                REQUIRE(bounded_euro.size() <= 255U);
                REQUIRE(bounded_euro.size() == 255U); // 85 whole characters
                REQUIRE(is_well_formed_utf8(bounded_euro));
                REQUIRE(bounded_euro.size() % 3U == 0U);
            }
        }

        WHEN("the string is bounded to a limit that falls inside a character")
        {
            auto const bounded = merovingian::database::bounded_utf8(euro, 254U);

            THEN("the partial character is dropped rather than emitted half-written")
            {
                REQUIRE(bounded.size() == 252U);
                REQUIRE(is_well_formed_utf8(bounded));
            }
        }
    }
}

SCENARIO("bounded_utf8 replaces invalid UTF-8 so stored and logged text stays well-formed", "[database][audit][utf8]")
{
    GIVEN("input holding a lone continuation byte, a truncated sequence, an overlong form and a surrogate")
    {
        auto const lone_continuation = std::string{"a\x80z"};
        auto const truncated = std::string{"a\xE2\x82"};
        auto const overlong = std::string{"a\xC0\xAF"
                                          "z"};
        auto const surrogate = std::string{"a\xED\xA0\x80z"};

        WHEN("each is bounded")
        {
            auto const one = merovingian::database::bounded_utf8(lone_continuation, 255U);
            auto const two = merovingian::database::bounded_utf8(truncated, 255U);
            auto const three = merovingian::database::bounded_utf8(overlong, 255U);
            auto const four = merovingian::database::bounded_utf8(surrogate, 255U);

            THEN("every result is well-formed UTF-8 and the valid bytes around the damage survive")
            {
                for (auto const* result : {&one, &two, &three, &four})
                {
                    REQUIRE(is_well_formed_utf8(*result));
                    REQUIRE(result->find(replacement) != std::string::npos);
                    REQUIRE(result->front() == 'a');
                }
                REQUIRE(one.back() == 'z');
                REQUIRE(three.back() == 'z');
                REQUIRE(four.back() == 'z');
            }
        }
    }
}

SCENARIO("bounded_utf8 replaces control characters so a value cannot forge log lines",
         "[database][audit][utf8][security]")
{
    GIVEN("a value carrying a newline, a NUL and a DEL")
    {
        auto hostile = std::string{"user\n2026-01-01 ERROR forged"};
        hostile.push_back('\0');
        hostile += "tail";
        hostile.push_back('\x7F');

        WHEN("it is bounded")
        {
            auto const bounded = merovingian::database::bounded_utf8(hostile, 255U);

            THEN("no control character remains")
            {
                REQUIRE(is_well_formed_utf8(bounded));
                for (auto const character : bounded)
                {
                    auto const byte = static_cast<unsigned char>(character);
                    REQUIRE(byte >= 0x20U);
                    REQUIRE(byte != 0x7FU);
                }
            }
        }
    }
}

SCENARIO("bounded_utf8 handles degenerate limits", "[database][audit][utf8]")
{
    GIVEN("an ordinary string")
    {
        WHEN("the limit is zero or smaller than a replacement character")
        {
            auto const zero = merovingian::database::bounded_utf8("abc", 0U);
            auto const tiny = merovingian::database::bounded_utf8(std::string{"\x80\x80"}, 2U);

            THEN("the result is empty or within the limit, never longer")
            {
                REQUIRE(zero.empty());
                REQUIRE(tiny.size() <= 2U);
            }
        }
    }
}

SCENARIO("append_audit_event bounds actor, target and reason before storing them",
         "[database][audit][persistence][security]")
{
    GIVEN("a persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("an audit event carries 60 KiB in each attacker-controlled field")
        {
            auto const huge = std::string(60U * 1024U, 'x');
            auto const appended =
                merovingian::database::append_audit_event(store, {"auth", "login.rejected", huge, huge, huge});

            THEN("the retained row holds at most 255 bytes per field")
            {
                REQUIRE(appended);
                REQUIRE(store.audit_log.size() == 1U);
                REQUIRE(store.audit_log.back().actor.size() <= merovingian::database::max_audit_field_bytes);
                REQUIRE(store.audit_log.back().target.size() <= merovingian::database::max_audit_field_bytes);
                REQUIRE(store.audit_log.back().reason.size() <= merovingian::database::max_audit_field_bytes);
            }
        }
    }
}

SCENARIO("The in-memory audit log keeps only the most recent events", "[database][audit][persistence][bounded]")
{
    GIVEN("a persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("far more audit events than the cap are appended")
        {
            auto const total = merovingian::database::max_in_memory_audit_events + 500U;
            for (auto i = std::size_t{0U}; i < total; ++i)
            {
                REQUIRE(merovingian::database::append_audit_event(
                    store, {"auth", "auth.login", "@alice:example.org", std::to_string(i), "ok"}));
            }

            THEN("the retained window is exactly the cap, holds the newest rows, and the evictions are counted")
            {
                REQUIRE(store.audit_log.size() == merovingian::database::max_in_memory_audit_events);
                REQUIRE(store.audit_log.back().target == std::to_string(total - 1U));
                REQUIRE(store.audit_log.front().target == std::to_string(total - store.audit_log.size()));
                REQUIRE(store.audit_log.size() + store.audit_log_evicted == total);
            }
        }
    }
}
