// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto make_create_event(std::string_view creator) -> std::string
{
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_"
           "events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_power_levels_event(std::string_view sender, std::int64_t ban_level, std::int64_t invite_level,
                                           std::int64_t kick_level, std::int64_t redact_level,
                                           std::int64_t users_default, std::int64_t state_default,
                                           std::int64_t events_default, std::string_view user_level_user,
                                           std::int64_t user_level) -> std::string
{
    return "{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"ban\":" + std::to_string(ban_level) +
           ",\"invite\":" + std::to_string(invite_level) + ",\"kick\":" + std::to_string(kick_level) +
           ",\"redact\":" + std::to_string(redact_level) + ",\"users_default\":" + std::to_string(users_default) +
           ",\"state_default\":" + std::to_string(state_default) +
           ",\"events_default\":" + std::to_string(events_default) + ",\"users\":{\"" + std::string{user_level_user} +
           "\":" + std::to_string(user_level) +
           "}},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],\"hashes\":{"
           "\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_member_event(std::string_view sender, std::string_view state_key, std::string_view membership)
    -> std::string
{
    return "{\"type\":\"m.room.member\",\"state_key\":\"" + std::string{state_key} + "\",\"sender\":\"" +
           std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{"
           "\"membership\":\"" +
           std::string{membership} +
           "\"},\"origin_server_ts\":3,\"depth\":2,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_join_rules_event(std::string_view join_rule) -> std::string
{
    return "{\"type\":\"m.room.join_rules\",\"state_key\":\"\",\"sender\":\"@alice:example.org\","
           "\"room_id\":\"!room:example.org\",\"content\":{\"join_rule\":\"" +
           std::string{join_rule} +
           "\"},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_message_event(std::string_view sender) -> std::string
{
    return "{\"type\":\"m.room.message\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"body\":\"hello\",\"msgtype\":\"m.text\"},"
           "\"origin_server_ts\":4,\"depth\":3,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_state_event(std::string_view sender, std::string_view type, std::string_view state_key)
    -> std::string
{
    return "{\"type\":\"" + std::string{type} + "\",\"state_key\":\"" + std::string{state_key} + "\",\"sender\":\"" +
           std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{},\"origin_server_ts\":5,\"depth\":4,"
           "\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

} // namespace

SCENARIO("Auth rules allow m.room.create event when room has no create event", "[events][auth][create]")
{
    GIVEN("a room with no existing create event in auth events")
    {
        auto const create_json = make_create_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(create_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};

        WHEN("the create event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed")
            {
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_step == "1");
            }
        }
    }
}

SCENARIO("Auth rules reject m.room.create when a create event already exists", "[events][auth][create]")
{
    GIVEN("a room with an existing create event")
    {
        auto const create_json = make_create_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(create_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto existing_create = merovingian::canonicaljson::parse_lossless(make_create_event("@bob:example.org"));
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = existing_create.value;

        WHEN("a second create event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "1");
            }
        }
    }
}

SCENARIO("Auth rules reject events when room has no create event", "[events][auth][create]")
{
    GIVEN("a message event in a room with no create event in auth events")
    {
        auto const msg_json = make_message_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};

        WHEN("the message event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "2");
            }
        }
    }
}

SCENARIO("Auth rules reject events from senders whose domain does not match the creator domain (v6+)",
         "[events][auth][sender-domain]")
{
    GIVEN("a room created by @alice:example.org and a sender from a different domain")
    {
        auto const msg_json = make_message_event("@eve:evil.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auto power = merovingian::canonicaljson::parse_lossless(
                         make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                         .value;
        auth_events.power_levels = power;
        auth_events.sender_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
                .value;

        WHEN("the event is authorized under v6+ rules")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected because the sender domain does not match the creator domain")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "3");
            }
        }
    }
}

SCENARIO("Auth rules allow a member join event when sender matches state_key and user is already joined",
         "[events][auth][membership]")
{
    GIVEN("a room where @alice:example.org is already joined")
    {
        auto const join_json = make_member_event("@alice:example.org", "@alice:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("invite")).value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed because the user is already joined")
            {
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_step == "5");
            }
        }
    }
}

SCENARIO("Auth rules reject a member join when sender does not match state_key", "[events][auth][membership]")
{
    GIVEN("a join event where @alice tries to set @bob's membership")
    {
        auto const join_json = make_member_event("@alice:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;

        WHEN("the join event is authorized (v6+)"
             "")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected because sender != state_key for a join")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "5");
            }
        }
    }
}

SCENARIO("Auth rules allow an invite when the inviter has sufficient power", "[events][auth][membership][invite]")
{
    GIVEN("a room where @alice has invite power and invites @bob")
    {
        auto const invite_json = make_member_event("@alice:example.org", "@bob:example.org", "invite");
        auto const parsed = merovingian::canonicaljson::parse_lossless(invite_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "leave"))
                                        .value;

        WHEN("the invite event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is allowed because the inviter has invite power and is joined")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject an invite when the inviter lacks invite power", "[events][auth][membership][invite]")
{
    GIVEN("a room where @alice has no invite power and tries to invite @bob")
    {
        auto const invite_json = make_member_event("@alice:example.org", "@bob:example.org", "invite");
        auto const parsed = merovingian::canonicaljson::parse_lossless(invite_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "leave"))
                                        .value;

        WHEN("the invite event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected due to insufficient power")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a self-leave event", "[events][auth][membership][leave]")
{
    GIVEN("a room where @alice is joined and leaves")
    {
        auto const leave_json = make_member_event("@alice:example.org", "@alice:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(leave_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the leave event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the self-leave is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a ban when the banner has sufficient power", "[events][auth][membership][ban]")
{
    GIVEN("a room where @alice has ban power and bans @bob")
    {
        auto const ban_json = make_member_event("@alice:example.org", "@bob:example.org", "ban");
        auto const parsed = merovingian::canonicaljson::parse_lossless(ban_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("the ban event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the ban is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a ban when the banner lacks ban power", "[events][auth][membership][ban]")
{
    GIVEN("a room where @alice has no ban power and tries to ban @bob")
    {
        auto const ban_json = make_member_event("@alice:example.org", "@bob:example.org", "ban");
        auto const parsed = merovingian::canonicaljson::parse_lossless(ban_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("the ban event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the ban is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow message events from joined members", "[events][auth][message]")
{
    GIVEN("a room where @alice is joined with default power")
    {
        auto const msg_json = make_message_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the message event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the message event is allowed because the sender is joined and has sufficient power")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject message events from non-joined senders", "[events][auth][message]")
{
    GIVEN("a room where @eve is not a member")
    {
        auto const msg_json = make_message_event("@eve:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auto power = merovingian::canonicaljson::parse_lossless(
                         make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:example.org", 0))
                         .value;
        auth_events.power_levels = power;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@eve:example.org", "@eve:example.org", "leave"))
                                        .value;

        WHEN("the message event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected because the sender is not joined")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow state events when sender has sufficient state_default power", "[events][auth][power-levels]")
{
    GIVEN("a room with state_default=50 and a sender with power=50")
    {
        auto const state_json = make_state_event("@alice:example.org", "m.room.name", "");
        auto const parsed = merovingian::canonicaljson::parse_lossless(state_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 50))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the state event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the state event is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject state events when sender lacks state_default power", "[events][auth][power-levels]")
{
    GIVEN("a room with state_default=50 and a sender with power=0")
    {
        auto const state_json = make_state_event("@alice:example.org", "m.room.name", "");
        auto const parsed = merovingian::canonicaljson::parse_lossless(state_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the state event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the state event is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow m.room.power_levels events from users with sufficient power", "[events][auth][power-levels]")
{
    GIVEN("a room where @alice has power=100 and sends a new power_levels event")
    {
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 100);
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the power_levels event is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject power level changes that elevate a user above the sender's own level",
         "[events][auth][power-levels]")
{
    GIVEN("a room where @alice has power=50 and tries to set @bob to power=60")
    {
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@bob:example.org", 60);
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 50))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected because it elevates a user above the sender")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a user to join a public room", "[events][auth][membership][join-rules]")
{
    GIVEN("a room with join_rule=public and @bob trying to join")
    {
        auto const join_json = make_member_event("@bob:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("public")).value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is allowed because the room is public")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a join to an invite-only room without an invite", "[events][auth][membership][join-rules]")
{
    GIVEN("a room with join_rule=invite and @bob trying to join without an invite")
    {
        auto const join_json = make_member_event("@bob:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("invite")).value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "leave"))
                                        .value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is rejected because the room is invite-only and the user was not invited")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a join to an invite-only room for a previously invited user",
         "[events][auth][membership][join-rules]")
{
    GIVEN("a room with join_rule=invite and @bob was previously invited")
    {
        auto const join_json = make_member_event("@bob:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("invite")).value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@bob:example.org", "invite"))
                                        .value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is allowed because the user was previously invited")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a kicked user to rejoin an invite-only room after a new invite",
         "[events][auth][membership][join-rules]")
{
    GIVEN("a room with join_rule=invite where @bob was kicked then re-invited")
    {
        auto const join_json = make_member_event("@bob:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("invite")).value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@bob:example.org", "invite"))
                                        .value;

        WHEN("the join event is authorized after re-invite")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject events with missing required fields", "[events][auth][validation]")
{
    GIVEN("an event JSON missing the sender field")
    {
        auto const bad_json =
            std::string{"{\"type\":\"m.room.message\",\"room_id\":\"!room:example.org\",\"content\":{\"body\":\"hi\"},"
                        "\"origin_server_ts\":4,\"depth\":3,\"prev_events\":[],\"auth_events\":[]}"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(bad_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};

        WHEN("authorization is attempted")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected for missing required fields")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules allow a kick when the kicker has sufficient kick power", "[events][auth][membership][kick]")
{
    GIVEN("a room where @alice has kick power=50 and kicks @bob who is joined")
    {
        auto const kick_json = make_member_event("@alice:example.org", "@bob:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(kick_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("the kick event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the kick is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a kick when the kicker lacks kick power", "[events][auth][membership][kick]")
{
    GIVEN("a room where @alice has power=0 and tries to kick @bob")
    {
        auto const kick_json = make_member_event("@alice:example.org", "@bob:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(kick_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("the kick event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the kick is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a user who is banned from joining", "[events][auth][membership][ban]")
{
    GIVEN("a room where @bob is banned and tries to join")
    {
        auto const join_json = make_member_event("@bob:example.org", "@bob:example.org", "join");
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("public")).value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@bob:example.org", "ban"))
                                        .value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is rejected because the user is banned")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}