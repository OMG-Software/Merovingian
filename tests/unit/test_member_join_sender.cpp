// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0612: the test that refuses, at receipt, one user joining another.
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/MemberJoinSender.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto parse(std::string const& raw) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

} // namespace

using merovingian::events::join_names_another_user;

SCENARIO("A join naming another user is told apart from every other membership event", "[gate-m][forged_join][events]")
{
    GIVEN("membership events of each shape")
    {
        auto const forged =
            parse(R"({"type":"m.room.member","sender":"@a:x","state_key":"@b:x","content":{"membership":"join"}})");
        auto const own =
            parse(R"({"type":"m.room.member","sender":"@a:x","state_key":"@a:x","content":{"membership":"join"}})");
        auto const invite =
            parse(R"({"type":"m.room.member","sender":"@a:x","state_key":"@b:x","content":{"membership":"invite"}})");
        auto const kick =
            parse(R"({"type":"m.room.member","sender":"@a:x","state_key":"@b:x","content":{"membership":"leave"}})");
        auto const other_type =
            parse(R"({"type":"m.room.topic","sender":"@a:x","state_key":"@b:x","content":{"membership":"join"}})");
        auto const no_state_key = parse(R"({"type":"m.room.member","sender":"@a:x","content":{"membership":"join"}})");
        auto const no_sender = parse(R"({"type":"m.room.member","state_key":"@b:x","content":{"membership":"join"}})");
        auto const no_content = parse(R"({"type":"m.room.member","sender":"@a:x","state_key":"@b:x"})");
        auto const not_an_object = parse(R"([1])");

        WHEN("each is judged")
        {
            THEN("only a join whose sender is not its state_key is one")
            {
                CHECK(join_names_another_user(forged));
                CHECK_FALSE(join_names_another_user(own));
                CHECK_FALSE(join_names_another_user(invite));
                CHECK_FALSE(join_names_another_user(kick));
                CHECK_FALSE(join_names_another_user(other_type));
                CHECK_FALSE(join_names_another_user(no_state_key));
                CHECK_FALSE(join_names_another_user(no_sender));
                CHECK_FALSE(join_names_another_user(no_content));
                CHECK_FALSE(join_names_another_user(not_an_object));
            }
        }
    }
}
