// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/statement.hpp"
#include "merovingian/events/event.hpp"
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>
#include <string>

SCENARIO("Database text boundaries reject NUL without rejecting binary bytes", "[database][db6]")
{
    GIVEN("a statement with an embedded NUL parameter")
    {
        auto statement = merovingian::database::PreparedStatement{"boundary", "INSERT INTO events VALUES ($1)", {{std::string{"\0x", 2}, false, false}}};
        WHEN("it is validated before execution")
        {
            auto const validation = merovingian::database::prepared_statement_is_valid(statement);
            THEN("text is rejected but the same binary payload is allowed")
            {
                REQUIRE_FALSE(validation.valid);
                statement.parameters.front().binary = true;
                REQUIRE(merovingian::database::prepared_statement_is_valid(statement).valid);
            }
        }
    }
}
SCENARIO("State keys containing NUL cannot enter the event pipeline", "[database][db6]")
{
    GIVEN("a valid state envelope except for its NUL state key")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(R"({"type":"m.room.name","sender":"@a:example.org","room_id":"!r:example.org","origin_server_ts":1,"content":{},"state_key":"\u0000x"})");
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        WHEN("the envelope is validated")
        {
            auto const result = merovingian::events::parse_event_envelope(parsed.value);
            THEN("it is rejected before persistence") { REQUIRE_FALSE(result.error.empty()); }
        }
    }
}
SCENARIO("NUL path components are rejected without truncation", "[database][db6]")
{
    GIVEN("encoded or literal NUL path components")
    {
        WHEN("the path decoder is called")
        {
            THEN("it rejects instead of returning an empty or truncated identifier")
            {
                REQUIRE_THROWS_AS(merovingian::core::percent_decode_path_component("%00x"), std::invalid_argument);
                REQUIRE_THROWS_AS(merovingian::core::percent_decode_path_component("x%00"), std::invalid_argument);
                REQUIRE_THROWS_AS(merovingian::core::percent_decode_path_component(std::string{"x\0y", 3}), std::invalid_argument);
                REQUIRE(merovingian::core::percent_decode_path_component("a+b%2Fc") == "a+b/c");
                REQUIRE(merovingian::core::percent_decode_path_component("").empty());
            }
        }
    }
}
