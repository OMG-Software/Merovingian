// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// core::FormFields: the strict application/x-www-form-urlencoded reader the OAuth 2.0 token, revocation and page
// endpoints read their bodies with (ADR-0765). Every departure from the grammar refuses the whole body.

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/FormFields.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using merovingian::core::ErrorCode;
using merovingian::core::FormFields;

// The code of a refusal, or ErrorCode::none when the body was read.
[[nodiscard]] auto refusal_code(std::variant<FormFields, merovingian::core::Error> const& parsed) -> ErrorCode
{
    auto const* error = std::get_if<merovingian::core::Error>(&parsed);
    return error == nullptr ? ErrorCode::none : error->code();
}

[[nodiscard]] auto repeated(std::string_view unit, std::size_t count) -> std::string
{
    auto out = std::string{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        out.append(unit);
    }
    return out;
}

} // namespace

SCENARIO("A form body is read into decoded fields", "[core][form]")
{
    GIVEN("an OAuth token request body with escapes, a plus and an empty value")
    {
        auto const body = std::string_view{
            "grant_type=authorization_code&code=abc%2Fdef&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1"
            "&note=two+words&state=&pad=a=b"};

        WHEN("it is parsed")
        {
            auto const parsed = FormFields::parse(body);

            THEN("every field is there, decoded, in body order")
            {
                auto const* fields = std::get_if<FormFields>(&parsed);
                REQUIRE(fields != nullptr);
                REQUIRE(fields->size() == 6U);
                REQUIRE(fields->find("grant_type") == std::optional<std::string_view>{"authorization_code"});
                REQUIRE(fields->find("code") == std::optional<std::string_view>{"abc/def"});
                REQUIRE(fields->find("redirect_uri") == std::optional<std::string_view>{"https://app.example/cb?x=1"});
                REQUIRE(fields->find("note") == std::optional<std::string_view>{"two words"});
                REQUIRE(fields->find("state") == std::optional<std::string_view>{""});
                REQUIRE(fields->find("pad") == std::optional<std::string_view>{"a=b"});
                REQUIRE_FALSE(fields->find("missing").has_value());
                REQUIRE(fields->fields().front().first == "grant_type");
                REQUIRE(fields->fields().back().first == "pad");
            }
        }
    }

    GIVEN("a body whose name is percent-encoded and whose value is UTF-8 in escapes")
    {
        WHEN("it is parsed")
        {
            auto const parsed = FormFields::parse("client%5Fid=caf%C3%A9");

            THEN("the name and the value are decoded")
            {
                auto const* fields = std::get_if<FormFields>(&parsed);
                REQUIRE(fields != nullptr);
                REQUIRE(fields->find("client_id") == std::optional<std::string_view>{"caf\xC3\xA9"});
            }
        }
    }

    GIVEN("an empty body")
    {
        WHEN("it is parsed")
        {
            auto const parsed = FormFields::parse("");

            THEN("it is an empty set, not an error")
            {
                auto const* fields = std::get_if<FormFields>(&parsed);
                REQUIRE(fields != nullptr);
                REQUIRE(fields->empty());
                REQUIRE(fields->size() == 0U);
            }
        }
    }
}

SCENARIO("A malformed form body is refused whole", "[core][form][security]")
{
    GIVEN("bodies with a bad escape, a raw byte an encoder escapes, or a broken field")
    {
        auto const hostile = std::array<std::string_view, 22U>{
            "a=%",           // escape with no digits
            "a=%2",          // escape with one digit
            "a=%zz",         // escape with no hex digit
            "a=%2g",         // second digit not hex
            "%=1",           // escape in the name
            "a",             // no '='
            "a=1&b",         // second field with no '='
            "=1",            // empty name
            "a=1&&b=2",      // empty field
            "&a=1",          // leading '&'
            "a=1&",          // trailing '&'
            "&",             // only a separator
            "a=b c",         // raw space
            "a=b\tc",        // raw tab
            "a=b\nc",        // raw line feed
            "a=\x7F",        // raw DEL
            "a=caf\xC3\xA9", // raw non-ASCII (an encoder escapes it)
            "a=%00",         // decoded NUL
            "a%00=1",        // decoded NUL in the name
            "a=%C0%AF",      // overlong UTF-8 for '/'
            "a=%ED%A0%80",   // UTF-16 surrogate
            "a=%FF",         // not UTF-8
        };

        WHEN("each is parsed")
        {
            THEN("each is refused as malformed")
            {
                for (auto const body : hostile)
                {
                    INFO("body bytes: " << body.size());
                    REQUIRE(refusal_code(FormFields::parse(body)) == ErrorCode::parse_failure);
                }
            }
        }
    }

    GIVEN("a body that sends one name twice")
    {
        WHEN("the second copy is spelled the same")
        {
            auto const parsed = FormFields::parse("client_id=good&client_id=evil");

            THEN("the body is refused, so no check can read one copy while another is used")
            {
                REQUIRE(refusal_code(parsed) == ErrorCode::parse_failure);
            }
        }

        WHEN("the second copy is percent-encoded")
        {
            auto const parsed = FormFields::parse("client_id=good&client%5fid=evil");

            THEN("names are compared decoded and the body is refused")
            {
                REQUIRE(refusal_code(parsed) == ErrorCode::parse_failure);
            }
        }
    }

    GIVEN("a refused body whose value is a secret")
    {
        auto const secret = std::string_view{"hunter2-secret-password"};
        auto const body = std::string{"password="} + std::string{secret} + "&password=x";

        WHEN("it is parsed")
        {
            auto const parsed = FormFields::parse(body);

            THEN("the error message does not repeat the input")
            {
                auto const* error = std::get_if<merovingian::core::Error>(&parsed);
                REQUIRE(error != nullptr);
                REQUIRE(error->message().find(secret) == std::string::npos);
                REQUIRE(error->message().find("password") == std::string::npos);
            }
        }
    }
}

SCENARIO("A form body is read up to each cap and refused one past it", "[core][form][boundary][security]")
{
    GIVEN("a body exactly the size cap and one a byte over")
    {
        auto const prefix = std::string{"v="};
        auto exact = prefix + std::string(FormFields::max_value_bytes, 'a');
        // Fill to the body cap with further fields of 8 KiB values.
        auto field = std::size_t{0U};
        while (exact.size() + 3U + FormFields::max_value_bytes < FormFields::max_body_bytes)
        {
            exact += "&" + std::string(1U, static_cast<char>('b' + field)) + "=" +
                     std::string(FormFields::max_value_bytes, 'a');
            ++field;
        }
        exact += "&z=" + std::string(FormFields::max_body_bytes - exact.size() - 3U, 'a');
        REQUIRE(exact.size() == FormFields::max_body_bytes);
        auto const over = exact + "a";

        WHEN("both are parsed")
        {
            auto const at_cap = FormFields::parse(exact);
            auto const past_cap = FormFields::parse(over);

            THEN("the one at the cap is read and the one over is refused, not cut")
            {
                REQUIRE(refusal_code(at_cap) == ErrorCode::none);
                REQUIRE(refusal_code(past_cap) == ErrorCode::invalid_argument);
            }
        }
    }

    GIVEN("bodies at and one past the field count cap")
    {
        auto at_cap = std::string{"f0=1"};
        for (auto index = std::size_t{1U}; index < FormFields::max_fields; ++index)
        {
            at_cap += "&f" + std::to_string(index) + "=1";
        }
        auto const over = at_cap + "&f" + std::to_string(FormFields::max_fields) + "=1";

        WHEN("both are parsed")
        {
            auto const read = FormFields::parse(at_cap);
            auto const refused = FormFields::parse(over);

            THEN("the cap is read whole and one more field is refused")
            {
                auto const* fields = std::get_if<FormFields>(&read);
                REQUIRE(fields != nullptr);
                REQUIRE(fields->size() == FormFields::max_fields);
                REQUIRE(refusal_code(refused) == ErrorCode::invalid_argument);
            }
        }
    }

    GIVEN("names and values at and one past their caps")
    {
        auto const name_at_cap = std::string(FormFields::max_name_bytes, 'n');
        auto const value_at_cap = std::string(FormFields::max_value_bytes, 'v');

        WHEN("each is parsed")
        {
            auto const name_ok = FormFields::parse(name_at_cap + "=1");
            auto const name_over = FormFields::parse(name_at_cap + "n=1");
            auto const value_ok = FormFields::parse("a=" + value_at_cap);
            auto const value_over = FormFields::parse("a=" + value_at_cap + "v");
            // Decoded length is what counts: three escaped bytes per decoded byte stay within the body cap.
            auto const escaped_over = FormFields::parse("a=" + repeated("%41", FormFields::max_value_bytes + 1U));

            THEN("the caps are inclusive and one more byte is refused")
            {
                REQUIRE(refusal_code(name_ok) == ErrorCode::none);
                REQUIRE(refusal_code(name_over) == ErrorCode::invalid_argument);
                REQUIRE(refusal_code(value_ok) == ErrorCode::none);
                REQUIRE(refusal_code(value_over) == ErrorCode::invalid_argument);
                REQUIRE(refusal_code(escaped_over) == ErrorCode::invalid_argument);
            }
        }
    }
}

SCENARIO("Moving a form keeps its fields and empties the source", "[core][form]")
{
    GIVEN("a parsed form")
    {
        auto parsed = FormFields::parse("password=secret");
        REQUIRE(std::holds_alternative<FormFields>(parsed));

        WHEN("it is moved into another and assigned over a third")
        {
            auto moved = std::move(std::get<FormFields>(parsed));
            auto assigned = std::get<FormFields>(FormFields::parse("other=1"));
            assigned = std::move(moved);

            THEN("the destination holds the field and the sources hold none")
            {
                REQUIRE(assigned.find("password") == std::optional<std::string_view>{"secret"});
                REQUIRE_FALSE(assigned.find("other").has_value());
                REQUIRE(std::get<FormFields>(parsed).empty());
            }
        }
    }
}
