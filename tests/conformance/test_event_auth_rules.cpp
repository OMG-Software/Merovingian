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
    // Spec: Matrix Server-Server API v1.18 — Room Version 12 (MSC4291)
    // v12 m.room.create MUST NOT include a room_id field. The room ID is
    // derived from the create event's reference hash after the fact.
    // m.federate is absent here — the room is federated (the default).
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_"
           "events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_non_federated_create_event(std::string_view creator) -> std::string
{
    // Same as make_create_event() but with content.m.federate set to false.
    // This activates the sender-domain restriction in auth rule step 3:
    // cross-domain senders MUST be rejected when m.federate is false.
    // Spec: Matrix Server-Server API v1.18 — Authorization Rules, Step 3.
    // URL: https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"m.federate\":false,\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_"
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

[[nodiscard]] auto make_member_event(std::string_view sender, std::string_view state_key,
                                     std::string_view membership) -> std::string
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

[[nodiscard]] auto make_state_event(std::string_view sender, std::string_view type,
                                    std::string_view state_key) -> std::string
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

// Spec: Matrix Server-Server API v1.18 — Authorization Rules, Step 3.
// URL: https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
//
// "If content.m.federate is false, and the domain of the sender does not match
//  the domain of the creator of the room, reject."
//
// The domain check is CONDITIONAL on m.federate:false. When absent or true,
// cross-domain senders are permitted.
SCENARIO("Auth rules reject cross-domain senders when m.federate is false (v6+)",
         "[events][auth][sender-domain][conformance]")
{
    GIVEN("a non-federated room (m.federate:false) created by @alice:example.org")
    {
        auto const msg_json = make_message_event("@eve:evil.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        // Use the non-federated create event so that the domain check fires.
        auth_events.create =
            merovingian::canonicaljson::parse_lossless(make_non_federated_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                .value;
        auth_events.sender_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
                .value;

        WHEN("the event from @eve:evil.org is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected — sender domain does not match creator domain and federation is disabled")
            {
                // Spec MUST: cross-domain sender rejected when m.federate is false.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "3");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Authorization Rules, Step 3.
// URL: https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
//
// The domain check at step 3 is ONLY triggered when content.m.federate is false.
// When m.federate is absent the room is federated and cross-domain senders are allowed.
SCENARIO("Auth rules allow cross-domain senders when m.federate is absent (v6+)",
         "[events][auth][sender-domain][conformance]")
{
    GIVEN("a federated room (m.federate absent) created by @alice:example.org")
    {
        auto const msg_json = make_message_event("@eve:evil.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        // Standard create event — no m.federate key — room is federated by default.
        auth_events.create =
            merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                .value;
        auth_events.sender_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
                .value;

        WHEN("the event from @eve:evil.org is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed — step 3 domain check does not apply when m.federate is absent")
            {
                // Spec MUST: absent m.federate means the room is federated; cross-domain
                // senders pass step 3 unconditionally.
                REQUIRE(decision.allowed);
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
        // MSC4289 (room v12): a room creator holds infinite power, so the low-power
        // actor (@alice) must NOT be the creator — @admin owns the room here.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
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
        // MSC4289 (room v12): a room creator holds infinite power, so the low-power
        // actor (@alice) must NOT be the creator — @admin owns the room here.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
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
        // MSC4289 (room v12): a room creator holds infinite power, so the low-power
        // actor (@alice) must NOT be the creator — @admin owns the room here.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
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

// Spec: Matrix Server-Server API v1.18 — Authorization Rules, Step 11.
// URL: https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
// Spec: Matrix Room Version 12 (MSC4289)
// URL: https://spec.matrix.org/v1.18/rooms/v12/
//
// A room creator (with effectively infinite power) is permitted to send a
// m.room.power_levels event, provided the new event does NOT list any creator
// in content.users (creators cannot be represented as an integer power level).
SCENARIO("Auth rules allow m.room.power_levels events from users with sufficient power", "[events][auth][power-levels][conformance]")
{
    GIVEN("a v12 room where @alice is the creator and she sets @bob's power to 50")
    {
        // The NEW power_levels event sets @bob's level only — NOT @alice's.
        // In v12, the creator (@alice) cannot appear in content.users of the new event;
        // only non-creator users may be listed there.
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@bob:example.org", 50);
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

            THEN("the power_levels event is allowed — creator grants a non-creator a finite power level")
            {
                // Spec MUST: a creator with infinite power can set non-creator power levels.
                REQUIRE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Version 12 (MSC4289)
// URL: https://spec.matrix.org/v1.18/rooms/v12/
//
// Room creators hold effectively infinite power that cannot be expressed as an
// integer. A m.room.power_levels event whose content.users lists the create-event
// sender or any additional_creators member MUST be rejected.
SCENARIO("Auth rules reject a power_levels event that lists the room creator in content.users (v12)",
         "[events][auth][power-levels][room-version][msc4289][conformance]")
{
    GIVEN("a v12 room where @alice is the creator and the new power_levels event has @alice in content.users")
    {
        // @alice is the create-event sender. Putting @alice in content.users of the
        // new power_levels event MUST cause rejection — her power is infinite and
        // cannot be expressed as an integer entry.
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@bob:example.org", 50))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected — a creator MUST NOT appear in content.users")
            {
                // Spec MUST: m.room.power_levels events that list a creator in content.users
                // MUST be rejected in room version 12.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "11");
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
        // MSC4289 (room v12): a room creator holds infinite power, so the elevating
        // sender (@alice) must NOT be the creator — @admin owns the room here.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
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

// --- MSC4289: privileged room creators (room version 12) ----------------------
// Spec: Matrix room version 12 (MSC4289 "Privilege room creators")
// URL: https://spec.matrix.org/latest/rooms/v12/
//
// In room version 12 the create event's sender and every user listed in the create
// event's content.additional_creators hold an effectively infinite power level: they
// outrank any integer in m.room.power_levels and need no explicit users entry. Room
// versions 10 and 11 have no such concept — those users are bound by the ordinary
// power-level rules. The behaviour MUST differ by room version.
SCENARIO("Room creators hold privileged power only in room version 12 (MSC4289)",
         "[events][auth][power-levels][room-version][msc4289]")
{
    GIVEN("a create event whose additional_creators lists @bob, and power_levels that omit @bob")
    {
        // @alice is the create sender (a creator); @bob is an additional creator.
        // Neither @bob nor a high state_default entry appears in power_levels: @bob
        // has only users_default (0) power under the ordinary rules.
        // Spec: v12 m.room.create MUST NOT include room_id — omitted here.
        auto const create_json =
            std::string{R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org",)"
                        R"("content":{"creator":"@alice:example.org",)"
                        R"("room_version":"12","additional_creators":["@bob:example.org"]},)"
                        R"("origin_server_ts":1,"depth":0,"prev_events":[],"auth_events":[],)"
                        R"("hashes":{"sha256":"hash"}})"};
        // state_default = 50, users_default = 0, only @alice present at 100.
        auto const power_json =
            make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100);
        // A state event (m.room.topic) sent by the additional creator @bob.
        auto const topic_json = make_state_event("@bob:example.org", "m.room.topic", "");

        auto make_auth = [&]() {
            auto auth_events = merovingian::events::AuthEventMap{};
            auth_events.create = merovingian::canonicaljson::parse_lossless(create_json).value;
            auth_events.power_levels = merovingian::canonicaljson::parse_lossless(power_json).value;
            auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                            make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                            .value;
            return auth_events;
        };
        auto const topic = merovingian::canonicaljson::parse_lossless(topic_json);
        REQUIRE(topic.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the additional creator sends a state event in a room version 12 room")
        {
            auto const* policy = merovingian::rooms::find_room_version_policy("12");
            REQUIRE(policy != nullptr);
            auto const auth_events = make_auth();
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(topic.value, *policy, auth_events);

            THEN("the creator's infinite power authorizes the event despite no power_levels entry")
            {
                REQUIRE(decision.allowed);
            }
        }

        WHEN("the same event is evaluated in room versions 10 and 11")
        {
            for (auto const* version : {"10", "11"})
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(version);
                REQUIRE(policy != nullptr);
                auto const auth_events = make_auth();
                auto const decision =
                    merovingian::events::authorize_event_against_auth_events(topic.value, *policy, auth_events);

                THEN("the user has no special privilege and lacks state_default power")
                {
                    // additional_creators carries no power meaning before v12, so @bob
                    // falls back to users_default (0) < state_default (50) and is rejected.
                    REQUIRE_FALSE(decision.allowed);
                }
            }
        }

        WHEN("the create event sender sends the same state event in room version 12")
        {
            // The create sender is also a creator under MSC4289, even with no users entry.
            auto const sender_topic =
                merovingian::canonicaljson::parse_lossless(make_state_event("@alice:example.org", "m.room.topic", ""));
            auto const* policy = merovingian::rooms::find_room_version_policy("12");
            REQUIRE(policy != nullptr);
            auto auth_events = make_auth();
            auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                            make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                            .value;
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(sender_topic.value, *policy, auth_events);

            THEN("the create sender is privileged and the event is allowed")
            {
                REQUIRE(decision.allowed);
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

// Spec: Matrix Room Version 8+ authorization rules for restricted joins.
// URL:  https://spec.matrix.org/v1.18/rooms/v8/#authorization-rules
//
// A restricted join without an invite is allowed when the event includes
// content.join_authorised_via_users_server naming a joined resident user with
// enough power to invite others.
SCENARIO("Auth rules allow a restricted-room join when join_authorised_via_users_server is valid",
         "[events][auth][membership][join-rules][restricted]")
{
    GIVEN("a restricted room where the resident server authorises the join through a joined user")
    {
        auto const join_json = std::string{
            "{\"type\":\"m.room.member\",\"state_key\":\"@bob:example.org\",\"sender\":\"@bob:example.org\","
            "\"room_id\":\"!room:example.org\",\"content\":{\"membership\":\"join\","
            "\"join_authorised_via_users_server\":\"@alice:example.org\"},"
            "\"origin_server_ts\":3,\"depth\":2,\"prev_events\":[],\"auth_events\":[],"
            "\"hashes\":{\"sha256\":\"hash\"}}"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(join_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 100))
                .value;
        auth_events.join_rules = merovingian::canonicaljson::parse_lossless(make_join_rules_event("restricted")).value;
        auth_events.authorising_user_member = merovingian::canonicaljson::parse_lossless(
                                                  make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                                  .value;

        WHEN("the join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the join is allowed because the resident server provided a valid authorising user")
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
        // MSC4289 (room v12): a room creator holds infinite power, so the low-power
        // actor (@alice) must NOT be the creator — @admin owns the room here.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
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

// ---------------------------------------------------------------------------
// Room version 1 auth rules differ from v6+
// Spec: https://spec.matrix.org/v1.18/rooms/v1/#authorization-rules
//
// In room versions 1–5, there is NO sender-domain check (the v6 rule that
// requires sender's domain to match the create event's creator domain does
// not exist). A cross-domain sender is therefore allowed in v1 rooms, provided
// all other rules are satisfied.
// ---------------------------------------------------------------------------

SCENARIO("Auth rules v1: cross-domain sender is NOT rejected (no domain check before v6)",
         "[events][auth][room-version][v1]")
{
    GIVEN("a room version 1 room created by @alice:example.org with a sender from evil.org")
    {
        // @eve:evil.org sends a message in a v1 room created by @alice:example.org.
        // In v6+ this would be rejected at rule step 3 (domain mismatch).
        // In v1 there is no such rule, so the event MUST be allowed.
        auto const msg_json = make_message_event("@eve:evil.org");
        auto const parsed   = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy_v1 = merovingian::rooms::find_room_version_policy("1");
        REQUIRE(policy_v1 != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create =
            merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                .value;
        auth_events.sender_member =
            merovingian::canonicaljson::parse_lossless(
                make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
                .value;

        WHEN("the event is authorized under room version 1 rules")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy_v1, auth_events);

            THEN("the event is allowed — v1 has no sender-domain check")
            {
                // Spec MUST: the v6 sender-domain rule does NOT apply in room versions 1–5.
                // Cross-domain senders are valid in v1 rooms.
                REQUIRE(decision.allowed);
            }
        }

        WHEN("the same event is authorized under room version 6 rules with m.federate:false")
        {
            // v6+ introduces a sender-domain check, but it is CONDITIONAL on
            // content.m.federate being false. Use a non-federated create event to
            // show that v6+ does enforce the check in that configuration.
            auto const* policy_v6 = merovingian::rooms::find_room_version_policy("6");
            REQUIRE(policy_v6 != nullptr);
            auto auth_events_nonfed = merovingian::events::AuthEventMap{};
            auth_events_nonfed.create =
                merovingian::canonicaljson::parse_lossless(make_non_federated_create_event("@alice:example.org")).value;
            auth_events_nonfed.power_levels =
                merovingian::canonicaljson::parse_lossless(
                    make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                    .value;
            auth_events_nonfed.sender_member =
                merovingian::canonicaljson::parse_lossless(
                    make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
                    .value;
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy_v6, auth_events_nonfed);

            THEN("the event is rejected at step 3 — v6+ enforces the domain check when m.federate is false")
            {
                // Spec MUST: the sender-domain check is introduced in room version 6,
                // conditional on content.m.federate being false in the create event.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "3");
            }
        }
    }
}

SCENARIO("Auth rules v1: create event is allowed even when sender domain differs from room_id domain",
         "[events][auth][room-version][v1]")
{
    GIVEN("a v1 create event (room versions 1-5 have no domain check)")
    {
        auto const create_json = make_create_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(create_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy_v1 = merovingian::rooms::find_room_version_policy("1");
        REQUIRE(policy_v1 != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};

        WHEN("the create event is authorized under v1")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy_v1, auth_events);

            THEN("the first create event is allowed in v1 (rule 1)")
            {
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_step == "1");
            }
        }
    }
}

SCENARIO("Auth rules: room version policies exist for all stable versions",
         "[events][auth][room-version]")
{
    GIVEN("a request for each stable Matrix room version")
    {
        auto constexpr stable_versions = std::array<char const*, 10>{
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
        };

        WHEN("each version policy is looked up")
        {
            THEN("all stable room versions have a registered policy")
            {
                for (auto const* ver : stable_versions)
                {
                    // Spec MUST: a compliant server MUST support all stable room versions.
                    // A null policy means the server cannot participate in that room type.
                    REQUIRE(merovingian::rooms::find_room_version_policy(ver) != nullptr);
                }
            }
        }
    }
}

SCENARIO("Auth rules: room version 11 and 12 are supported",
         "[events][auth][room-version]")
{
    GIVEN("a request for room versions 11 and 12")
    {
        WHEN("version 11 and 12 policies are looked up")
        {
            THEN("both are registered")
            {
                REQUIRE(merovingian::rooms::find_room_version_policy("11") != nullptr);
                REQUIRE(merovingian::rooms::find_room_version_policy("12") != nullptr);
            }
        }
    }
}
