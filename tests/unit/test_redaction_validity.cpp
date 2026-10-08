// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// CSAZ-11: whether a redaction applies to its target, and where a room version keeps `redacts`.
//
// Spec: rooms/v3.md ... rooms/v12.md "Handling redactions": the server applies a redaction if the
// redaction sender's power level is at least the redact level, or the redaction sender's domain
// matches the original event sender's domain.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/redaction_validity.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::events::RedactionContext;
using merovingian::events::RedactionVerdict;

[[nodiscard]] auto parse(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto policy_for(char const* version) -> merovingian::rooms::RoomVersionPolicy const&
{
    auto const* policy = merovingian::rooms::find_room_version_policy(version);
    REQUIRE(policy != nullptr);
    return *policy;
}

[[nodiscard]] auto power_levels(std::string const& users) -> merovingian::canonicaljson::Value
{
    return parse(R"({"type":"m.room.power_levels","state_key":"","content":{"users":)" + users +
                 R"(,"redact":50,"events_default":0}})");
}

[[nodiscard]] auto create_event() -> merovingian::canonicaljson::Value
{
    return parse(R"({"type":"m.room.create","state_key":"","sender":"@admin:a.example",)"
                 R"("content":{"room_version":"10","creator":"@admin:a.example"}})");
}

[[nodiscard]] auto message_from(std::string const& sender) -> merovingian::canonicaljson::Value
{
    return parse(R"({"type":"m.room.message","sender":")" + sender + R"(","content":{"body":"x"}})");
}

} // namespace

SCENARIO("A redaction's target is read from the location its room version uses",
         "[csaz-11][redaction][events][room-versions]")
{
    GIVEN("redaction events with redacts at the top level and in content")
    {
        auto const top_level = parse(R"({"type":"m.room.redaction","redacts":"$old","content":{}})");
        auto const in_content = parse(R"({"type":"m.room.redaction","content":{"redacts":"$new"}})");

        THEN("room v10 reads the top-level property and ignores content")
        {
            REQUIRE(merovingian::events::redaction_target(top_level, policy_for("10")) ==
                    std::optional<std::string>{"$old"});
            REQUIRE(!merovingian::events::redaction_target(in_content, policy_for("10")).has_value());
        }

        THEN("room v11 and v12 read content.redacts and ignore the top-level property")
        {
            REQUIRE(merovingian::events::redaction_target(in_content, policy_for("11")) ==
                    std::optional<std::string>{"$new"});
            REQUIRE(merovingian::events::redaction_target(in_content, policy_for("12")) ==
                    std::optional<std::string>{"$new"});
            REQUIRE(!merovingian::events::redaction_target(top_level, policy_for("11")).has_value());
        }

        THEN("an event that is not a redaction names no target")
        {
            REQUIRE(!merovingian::events::redaction_target(message_from("@a:a.example"), policy_for("10")).has_value());
        }
    }
}

SCENARIO("A redaction applies on power level or on a matching sender domain",
         "[csaz-11][redaction][events][power-levels]")
{
    GIVEN("a room where @mod:b.example has level 50, @low:b.example has level 0 and redact is 50")
    {
        auto const context = RedactionContext{
            power_levels(R"({"@admin:a.example":100,"@mod:b.example":50})"),
            create_event(),
        };
        auto const& policy = policy_for("10");
        auto const target_from_a = message_from("@alice:a.example");

        WHEN("a user at the redact level redacts an event from another server")
        {
            auto const redaction = parse(R"({"type":"m.room.redaction","sender":"@mod:b.example","redacts":"$t"})");

            THEN("it applies (condition 1: power level at least the redact level)")
            {
                REQUIRE(merovingian::events::judge_redaction(redaction, target_from_a, context, policy) ==
                        RedactionVerdict::applies);
            }
        }

        WHEN("a user below the redact level redacts an event from another server")
        {
            auto const redaction = parse(R"({"type":"m.room.redaction","sender":"@low:b.example","redacts":"$t"})");

            THEN("it does not apply")
            {
                REQUIRE(merovingian::events::judge_redaction(redaction, target_from_a, context, policy) ==
                        RedactionVerdict::sender_lacks_authority);
            }
        }

        WHEN("a user below the redact level redacts an event from their own server")
        {
            auto const redaction = parse(R"({"type":"m.room.redaction","sender":"@low:b.example","redacts":"$t"})");
            auto const target_from_b = message_from("@bob:b.example");

            THEN("it applies (condition 2: matching domains)")
            {
                REQUIRE(merovingian::events::judge_redaction(redaction, target_from_b, context, policy) ==
                        RedactionVerdict::applies);
            }
        }

        WHEN("there is no power levels event, and the creator redacts")
        {
            auto const no_power_levels = RedactionContext{{}, create_event()};
            auto const by_creator = parse(R"({"type":"m.room.redaction","sender":"@admin:a.example","redacts":"$t"})");
            auto const by_other = parse(R"({"type":"m.room.redaction","sender":"@low:b.example","redacts":"$t"})");

            THEN("the creator's default level 100 meets the default redact level 50, another server's user does not")
            {
                REQUIRE(merovingian::events::judge_redaction(by_creator, message_from("@x:c.example"), no_power_levels,
                                                             policy) == RedactionVerdict::applies);
                REQUIRE(merovingian::events::judge_redaction(by_other, message_from("@x:c.example"), no_power_levels,
                                                             policy) == RedactionVerdict::sender_lacks_authority);
            }
        }

        WHEN("the target is the room's m.room.create event")
        {
            auto const redaction = parse(R"({"type":"m.room.redaction","sender":"@mod:b.example","redacts":"$c"})");

            THEN("it is never applied: the server derives the room version from that event")
            {
                REQUIRE(merovingian::events::judge_redaction(redaction, create_event(), context, policy) ==
                        RedactionVerdict::target_not_redactable);
            }
        }
    }
}

SCENARIO("A malformed redaction names no target", "[csaz-11][redaction][events]")
{
    GIVEN("events that are not usable redactions")
    {
        auto const& v10 = policy_for("10");
        auto const& v11 = policy_for("11");
        auto const not_an_object = parse(R"(["m.room.redaction"])");
        auto const wrong_type = parse(R"({"type":"m.room.message","redacts":"$x"})");
        auto const no_content_v11 = parse(R"({"type":"m.room.redaction","redacts":"$x"})");
        auto const empty_target = parse(R"({"type":"m.room.redaction","redacts":""})");

        WHEN("their targets are read")
        {
            auto const from_array = merovingian::events::redaction_target(not_an_object, v10);
            auto const from_message = merovingian::events::redaction_target(wrong_type, v10);
            auto const v11_without_content = merovingian::events::redaction_target(no_content_v11, v11);
            auto const from_empty = merovingian::events::redaction_target(empty_target, v10);

            THEN("none of them names an event")
            {
                REQUIRE_FALSE(from_array.has_value());
                REQUIRE_FALSE(from_message.has_value());
                REQUIRE_FALSE(v11_without_content.has_value());
                REQUIRE_FALSE(from_empty.has_value());
            }
        }
    }
}

SCENARIO("A redaction without a sender, or of a malformed target, never applies", "[csaz-11][redaction][events]")
{
    GIVEN("a room version 10 context in which the redact level is 50")
    {
        auto const& v10 = policy_for("10");
        auto const context = RedactionContext{power_levels(R"({"@admin:a.example":100})"), create_event()};
        auto const redaction_without_sender = parse(R"({"type":"m.room.redaction","redacts":"$x"})");
        auto const redaction_by_admin =
            parse(R"({"type":"m.room.redaction","sender":"@admin:a.example","redacts":"$x"})");
        auto const target_not_an_object = parse(R"(["m.room.message"])");

        WHEN("a redaction with no sender is judged, and an administrator's redaction of a malformed target")
        {
            auto const no_sender = merovingian::events::judge_redaction(redaction_without_sender,
                                                                        message_from("@bob:a.example"), context, v10);
            auto const malformed_target =
                merovingian::events::judge_redaction(redaction_by_admin, target_not_an_object, context, v10);
            auto const sender_power =
                merovingian::events::sender_meets_redact_level(redaction_without_sender, context, v10);

            THEN("neither applies, and a sender that is missing has no power")
            {
                REQUIRE(no_sender == RedactionVerdict::sender_lacks_authority);
                REQUIRE(malformed_target == RedactionVerdict::sender_lacks_authority);
                REQUIRE_FALSE(sender_power);
            }
        }
    }
}
