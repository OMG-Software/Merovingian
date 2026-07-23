// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

namespace
{

[[nodiscard]] auto make_create_event(std::string_view creator) -> std::string
{
    // Spec: Matrix Server-Server API v1.19 — Room Version 12 (MSC4291)
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
    // Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 3.
    // URL: ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"m.federate\":false,\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],"
           "\"auth_"
           "events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_v1_create_event(std::string_view creator) -> std::string
{
    // Spec: Matrix Room Version 1 — ../../docs/matrix-v1.19-spec/rooms/v1.md
    // Room versions 1–10 MUST include room_id in every PDU, including the
    // create event. The room_id is assigned by the creating server (not derived
    // from a hash as in v12/MSC4291). content.creator is required in v1–v10;
    // content.room_version was introduced in v7/MSC1773 and is absent here.
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_v1_non_federated_create_event(std::string_view creator) -> std::string
{
    // Same as make_v1_create_event() but with content.m.federate set to false.
    // Used in pre-v6 room contexts to test the absence of the domain check in v1,
    // and in v6 contexts to verify that the domain check fires when federation is
    // explicitly disabled. v1–v10 create events carry room_id; content.room_version
    // is absent (introduced in v7).
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"m.federate\":false},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
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

[[nodiscard]] auto make_power_levels_event_users(std::string_view sender, std::int64_t ban_level,
                                                 std::int64_t invite_level, std::int64_t kick_level,
                                                 std::int64_t redact_level, std::int64_t users_default,
                                                 std::int64_t state_default, std::int64_t events_default,
                                                 std::vector<std::pair<std::string, std::int64_t>> const& users)
    -> std::string
{
    // Like make_power_levels_event() but allows multiple entries in content.users,
    // so auth-rule 9.8 ("changed in, or removed from") can be exercised by omitting
    // a user that was present in the prior power_levels event.
    auto users_json = std::string{};
    for (auto const& [user_id, level] : users)
    {
        if (!users_json.empty())
        {
            users_json += ',';
        }
        users_json += "\"" + user_id + "\":" + std::to_string(level);
    }
    return "{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"ban\":" + std::to_string(ban_level) +
           ",\"invite\":" + std::to_string(invite_level) + ",\"kick\":" + std::to_string(kick_level) +
           ",\"redact\":" + std::to_string(redact_level) + ",\"users_default\":" + std::to_string(users_default) +
           ",\"state_default\":" + std::to_string(state_default) +
           ",\"events_default\":" + std::to_string(events_default) + ",\"users\":{" + users_json +
           "}},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":"
           "\"hash\"}}";
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

[[nodiscard]] auto make_redaction_event(std::string_view sender, std::string_view redacts) -> std::string
{
    return "{\"type\":\"m.room.redaction\",\"sender\":\"" + std::string{sender} + "\",\"redacts\":\"" +
           std::string{redacts} + "\",\"room_id\":\"!room:example.org\",\"content\":{\"redacts\":\"" +
           std::string{redacts} +
           "\"},\"origin_server_ts\":4,\"depth\":3,\"prev_events\":[],\"auth_events\":[],"
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

// Spec: client-server-api.md#mroomthird_party_invite
[[nodiscard]] auto make_third_party_invite_event(std::string_view sender, std::string_view token,
                                                 std::string_view public_key_b64) -> std::string
{
    return "{\"type\":\"m.room.third_party_invite\",\"state_key\":\"" + std::string{token} + "\",\"sender\":\"" +
           std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"display_name\":\"Alice\",\"key_validity_url\":"
           "\"https://example.org/key\",\"public_key\":\"" +
           std::string{public_key_b64} +
           "\"},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

// Like make_third_party_invite_event() but carries the public key list form
// (content.public_keys) instead of the single legacy content.public_key.
[[nodiscard]] auto make_third_party_invite_event_with_keys_list(std::string_view sender, std::string_view token,
                                                                std::string_view public_key_b64) -> std::string
{
    return "{\"type\":\"m.room.third_party_invite\",\"state_key\":\"" + std::string{token} + "\",\"sender\":\"" +
           std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"display_name\":\"Alice\",\"public_keys\":[{"
           "\"public_key\":\"not-the-right-key\"},{\"public_key\":\"" +
           std::string{public_key_b64} +
           "\"}]},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

// Signs the canonical {"mxid":..,"sender":..,"token":..} payload (field order is
// already alphabetical, matching canonical JSON with "signatures" stripped) and
// returns the invite's m.room.member event JSON with content.third_party_invite
// populated per client-server-api.md's Third-party Signed shape.
[[nodiscard]] auto make_third_party_signed_member_event(std::string_view inviter, std::string_view invitee_mxid,
                                                        std::string_view signed_sender, std::string_view token,
                                                        std::string_view signature_domain,
                                                        std::string_view signature_key_id,
                                                        std::string_view signature_b64) -> std::string
{
    return "{\"type\":\"m.room.member\",\"state_key\":\"" + std::string{invitee_mxid} + "\",\"sender\":\"" +
           std::string{inviter} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"membership\":\"invite\",\"third_party_invite\":{"
           "\"display_name\":\"Alice\",\"signed\":{\"mxid\":\"" +
           std::string{invitee_mxid} + "\",\"sender\":\"" + std::string{signed_sender} + "\",\"token\":\"" +
           std::string{token} + "\",\"signatures\":{\"" + std::string{signature_domain} + "\":{\"" +
           std::string{signature_key_id} + "\":\"" + std::string{signature_b64} +
           "\"}}}}},\"origin_server_ts\":3,\"depth\":2,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto sign_third_party_invite_payload(std::string_view mxid, std::string_view sender,
                                                   std::string_view token, std::string const& secret_key_bytes)
    -> std::string
{
    auto const payload = "{\"mxid\":\"" + std::string{mxid} + "\",\"sender\":\"" + std::string{sender} +
                         "\",\"token\":\"" + std::string{token} + "\"}";
    return merovingian::federation::test::sign_payload_b64(payload, secret_key_bytes);
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

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 3.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
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

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 3.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
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
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Room Version 12
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
// "If membership is leave: 1. If the sender matches state_key, allow if and
// only if that user's current membership state is invite, join, or knock."
// A banned user's current membership is `ban`, which is not in that set, so a
// self-leave from `ban` MUST be rejected — otherwise a banned user could
// unban themselves by sending membership=leave and then rejoin/knock.
SCENARIO("Auth rules reject a self-leave event from a banned user", "[events][auth][membership][leave][security]")
{
    GIVEN("a room where @alice is banned and sends a self-leave")
    {
        auto const leave_json = make_member_event("@alice:example.org", "@alice:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(leave_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@bob:example.org")).value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@alice:example.org", "ban"))
                                        .value;

        WHEN("the self-leave event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the self-leave is rejected (banned user cannot unban themselves)")
            {
                // Spec MUST: self-leave is only allowed from invite, join, or knock.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Room Version 12
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
// Same rule as above: a user with no prior membership (never joined, invited,
// or knocked) has an implicit current membership of `leave`, which is not in
// {invite, join, knock} — a bare self-leave with no supporting state MUST be
// rejected.
SCENARIO("Auth rules reject a self-leave event with no prior membership", "[events][auth][membership][leave][security]")
{
    GIVEN("a room where @alice has never joined and sends a self-leave")
    {
        auto const leave_json = make_member_event("@alice:example.org", "@alice:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(leave_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@bob:example.org")).value;
        // No auth_events.sender_member set — @alice has no prior membership event.

        WHEN("the self-leave event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the self-leave is rejected")
            {
                // Spec MUST: self-leave is only allowed from invite, join, or knock;
                // a user who was never a member has an implicit membership of leave.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Room Version 12
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
// "If membership is ... 8. Otherwise, the membership is unknown. Reject."
SCENARIO("Auth rules reject a member event with an unrecognized membership value",
         "[events][auth][membership][security]")
{
    GIVEN("a room where @alice sends an m.room.member event with a garbage membership value")
    {
        auto const garbage_json = make_member_event("@alice:example.org", "@alice:example.org", "wizard");
        auto const parsed = merovingian::canonicaljson::parse_lossless(garbage_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;

        WHEN("the event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected as an unknown membership transition")
            {
                // Spec MUST: an unrecognized membership value is rejected, not
                // silently treated as any known transition (e.g. leave).
                REQUIRE_FALSE(decision.allowed);
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
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
        // In v12 @alice is the room creator (infinite power). The creator MUST NOT appear in
        // content.users of m.room.power_levels. Use @moderator as the explicit user entry.
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 0))
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
        // In v12 @alice is the room creator (infinite power). The creator MUST NOT appear in
        // content.users of m.room.power_levels. Use @moderator as the explicit user entry.
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 50))
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

// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 11.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
// Spec: Matrix Room Version 12 (MSC4289)
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// A room creator (with effectively infinite power) is permitted to send a
// m.room.power_levels event, provided the new event does NOT list any creator
// in content.users (creators cannot be represented as an integer power level).
SCENARIO("Auth rules allow m.room.power_levels events from users with sufficient power",
         "[events][auth][power-levels][conformance]")
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
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

// Spec: Matrix Room Version 12 (MSC4289) — Authorization Rules, rule 9.9
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// "For each entry being added to, or changed in, the users property: If the new
// value is greater than the sender's current power level, reject." Unlike rule 9.8
// (demotion), rule 9.9 carries NO "other than the sender's own entry" carve-out, so
// the sender MUST NOT be able to elevate their own power above their current level.
SCENARIO("Auth rules reject a sender self-elevating their own power above their current level",
         "[events][auth][power-levels][conformance]")
{
    GIVEN("a v12 room where non-creator @alice has power=50 and tries to set herself to power=100")
    {
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 100);
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        // @alice must NOT be the creator (creators have infinite power in v12).
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

            THEN("the event is rejected — rule 9.9 has no sender self-exemption")
            {
                // Spec MUST: the new value (100) is greater than the sender's current
                // power level (50); the sender is NOT exempt from rule 9.9.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "11");
            }
        }
    }

    GIVEN("a v12 room where non-creator @alice has power=50 and keeps herself at power=50")
    {
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@alice:example.org", 50);
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
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

            THEN("the event is allowed — the sender may keep or demote their own level")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Version 12 (MSC4289) — Authorization Rules, rule 9.8
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// "For each entry being changed in, or removed from, the users property, other than
// the sender's own entry: If the current value is greater than or equal to the
// sender's current power level, reject." This covers both modification AND removal
// (a user omitted from the new content.users is "removed from" the property) and
// uses "greater than or equal to" — so demoting an equal-power peer is also rejected.
SCENARIO("Auth rules reject removal or demotion of a user at or above the sender's power",
         "[events][auth][power-levels][conformance]")
{
    GIVEN("a v12 room where @admin has power=100, @alice has power=50, and @alice omits @admin from the new event")
    {
        // Prior power_levels: @admin=100, @alice=50. New event from @alice (50, meeting
        // state_default=50) lists only herself — @admin is REMOVED from content.users.
        auto const pl_json = make_power_levels_event_users("@alice:example.org", 50, 0, 50, 50, 0, 50, 0,
                                                           {
                                                               {"@alice:example.org", 50}
        });
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@admin:example.org", 50, 0, 50, 50, 0, 50, 0,
                                              {
                                                  {"@admin:example.org", 100},
                                                  {"@alice:example.org", 50 }
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected — removing a superior user is forbidden by rule 9.8")
            {
                // Spec MUST: the current value (100) is >= the sender's power (50); the
                // removed entry is "removed from" the users property and is not the
                // sender's own entry.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "11");
            }
        }
    }

    GIVEN("a v12 room where @bob and @alice both have power=50, and @alice demotes @bob to 0")
    {
        // Prior power_levels lists only the two equal-power peers (no superior). The
        // room creator @admin (infinite power) is intentionally absent from users so
        // that the only rule in play is 9.8's "greater than or equal to" demotion check.
        auto const pl_json = make_power_levels_event_users("@alice:example.org", 50, 0, 50, 50, 0, 50, 0,
                                                           {
                                                               {"@alice:example.org", 50},
                                                               {"@bob:example.org",   0 }
        });
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@admin:example.org", 50, 0, 50, 50, 0, 50, 0,
                                              {
                                                  {"@alice:example.org", 50},
                                                  {"@bob:example.org",   50}
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected — demoting an equal-power peer is forbidden (>=)")
            {
                // Spec MUST: the current value (50) is >= the sender's power (50); the
                // "greater than or equal to" wording forbids demoting an equal-power peer.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "11");
            }
        }
    }

    GIVEN("a v12 room where @alice has power=50 and demotes a lower-power @carol from 20 to 0")
    {
        auto const pl_json = make_power_levels_event_users("@alice:example.org", 50, 0, 50, 50, 0, 50, 0,
                                                           {
                                                               {"@alice:example.org", 50},
                                                               {"@carol:example.org", 0 }
        });
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        // No superior present: only @alice (50) and the lower-power @carol (20). The
        // creator @admin (infinite power) is absent from users so nothing else triggers.
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@admin:example.org", 50, 0, 50, 50, 0, 50, 0,
                                              {
                                                  {"@alice:example.org", 50},
                                                  {"@carol:example.org", 20}
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed — demoting a lower-power user is permitted")
            {
                REQUIRE(decision.allowed);
            }
        }
    }

    GIVEN("a v12 room where @admin is the creator and removes a lower-power @alice (50) from the new event")
    {
        // @admin (the creator, infinite power) authors a new power_levels event with an
        // empty users map — @alice (50) is removed and the creator is NOT listed (a
        // creator must not appear in content.users). Since 50 < infinite, rule 9.8 does
        // not forbid the removal.
        auto const pl_json = make_power_levels_event_users("@admin:example.org", 50, 0, 50, 50, 0, 50, 0, {});
        auto const parsed = merovingian::canonicaljson::parse_lossless(pl_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@admin:example.org", 50, 0, 50, 50, 0, 50, 0,
                                              {
                                                  {"@admin:example.org", 100},
                                                  {"@alice:example.org", 50 }
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@admin:example.org", "@admin:example.org", "join"))
                                        .value;

        WHEN("the power_levels event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed — removing a lower-power user is permitted")
            {
                REQUIRE(decision.allowed);
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
        auto const create_json = std::string{R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org",)"
                                             R"("content":{"creator":"@alice:example.org",)"
                                             R"("room_version":"12","additional_creators":["@bob:example.org"]},)"
                                             R"("origin_server_ts":1,"depth":0,"prev_events":[],"auth_events":[],)"
                                             R"("hashes":{"sha256":"hash"}})"};
        // state_default = 50, users_default = 0. @alice is the room creator (infinite
        // power in v12) so she MUST NOT appear in content.users; use @moderator instead.
        auto const power_json =
            make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100);
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
// URL:  ../../docs/matrix-v1.19-spec/rooms/v8.md#authorization-rules
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
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@moderator:example.org", 100))
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
// Spec: ../../docs/matrix-v1.19-spec/rooms/v1.md#authorization-rules
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
        auto const parsed = merovingian::canonicaljson::parse_lossless(msg_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy_v1 = merovingian::rooms::find_room_version_policy("1");
        REQUIRE(policy_v1 != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        // v1 room: use the v1-valid create fixture (carries room_id; no room_version in content).
        auth_events.create =
            merovingian::canonicaljson::parse_lossless(make_v1_create_event("@alice:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                .value;
        auth_events.sender_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
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
            // v6 create events carry room_id (like all pre-v12 PDUs).
            auto const* policy_v6 = merovingian::rooms::find_room_version_policy("6");
            REQUIRE(policy_v6 != nullptr);
            auto auth_events_nonfed = merovingian::events::AuthEventMap{};
            auth_events_nonfed.create =
                merovingian::canonicaljson::parse_lossless(make_v1_non_federated_create_event("@alice:example.org"))
                    .value;
            auth_events_nonfed.power_levels =
                merovingian::canonicaljson::parse_lossless(
                    make_power_levels_event("@alice:example.org", 50, 0, 50, 50, 0, 50, 0, "@eve:evil.org", 0))
                    .value;
            auth_events_nonfed.sender_member =
                merovingian::canonicaljson::parse_lossless(make_member_event("@eve:evil.org", "@eve:evil.org", "join"))
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
        // Use the v1-valid fixture: includes room_id, no room_version in content.
        auto const create_json = make_v1_create_event("@alice:example.org");
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

SCENARIO("Auth rules: room version policies exist for all stable versions", "[events][auth][room-version]")
{
    GIVEN("a request for each stable Matrix room version")
    {
        auto constexpr stable_versions = std::array<char const*, 10>{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};

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

SCENARIO("Auth rules: room version 11 and 12 are supported", "[events][auth][room-version]")
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

// ---------------------------------------------------------------------------
// Auth rule step 2: every non-create event requires a create event in auth_events.
// Spec: Matrix Server-Server API v1.19 — Authorization Rules
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
// ---------------------------------------------------------------------------

SCENARIO("Auth rules reject a non-create event when auth_events contains no create event",
         "[events][auth][validation][conformance]")
{
    GIVEN("a message event and an empty auth event map (no create event)")
    {
        auto const message_json = make_message_event("@alice:example.org");
        auto const parsed = merovingian::canonicaljson::parse_lossless(message_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        // auth_events.create is empty — simulate a room where no create event is provided.
        auto auth_events = merovingian::events::AuthEventMap{};

        WHEN("the message event is authorized without a room create event")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected — the auth chain must include a create event")
            {
                // Spec MUST: if there is no m.room.create event in the auth chain, reject
                // all events except m.room.create itself.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Knock join rule (room v7+)
// Spec: Matrix Server-Server API v1.19 — Authorization Rules, membership
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
// ---------------------------------------------------------------------------

SCENARIO("Auth rules allow a knock when join_rule is knock and sender matches state_key",
         "[events][auth][membership][knock][conformance]")
{
    GIVEN("a room with join_rule=knock and a user who wishes to knock")
    {
        auto const create_json = make_create_event("@alice:example.org");
        auto const join_rules_json = make_join_rules_event("knock");

        auto const parsed_create = merovingian::canonicaljson::parse_lossless(create_json);
        auto const parsed_join_rules = merovingian::canonicaljson::parse_lossless(join_rules_json);
        REQUIRE(parsed_create.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_join_rules.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parsed_create.value;
        auth_events.join_rules = parsed_join_rules.value;
        // sender_member is absent — the user is not yet in the room.

        // Knock event: sender and state_key are the same user.
        auto const knock_json = make_member_event("@bob:example.org", "@bob:example.org", "knock");
        auto const parsed_knock = merovingian::canonicaljson::parse_lossless(knock_json);
        REQUIRE(parsed_knock.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the knock event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed_knock.value, *policy, auth_events);

            THEN("the knock is allowed — join_rule permits knocking")
            {
                // Spec MUST: membership=knock is allowed when join_rule is "knock"
                // and sender matches state_key.
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a knock when join_rule is not knock or knock_restricted",
         "[events][auth][membership][knock][conformance]")
{
    GIVEN("a room with join_rule=public and a knock event")
    {
        auto const create_json = make_create_event("@alice:example.org");
        auto const join_rules_json = make_join_rules_event("public");

        auto const parsed_create = merovingian::canonicaljson::parse_lossless(create_json);
        auto const parsed_join_rules = merovingian::canonicaljson::parse_lossless(join_rules_json);
        REQUIRE(parsed_create.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_join_rules.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parsed_create.value;
        auth_events.join_rules = parsed_join_rules.value;

        auto const knock_json = make_member_event("@bob:example.org", "@bob:example.org", "knock");
        auto const parsed_knock = merovingian::canonicaljson::parse_lossless(knock_json);
        REQUIRE(parsed_knock.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the knock event is authorized in a public room")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed_knock.value, *policy, auth_events);

            THEN("the knock is rejected — the room does not allow knocking")
            {
                // Spec MUST: membership=knock is only valid when join_rule is
                // "knock" or "knock_restricted". A public room MUST reject it.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kick power-level comparison: sender PL must STRICTLY exceed target PL.
// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 5
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
// ---------------------------------------------------------------------------

SCENARIO("Auth rules reject a kick when the sender's power level equals the target's",
         "[events][auth][membership][kick][conformance]")
{
    GIVEN("a room where both sender and target hold power level 50")
    {
        auto const create_json = make_create_event("@alice:example.org");
        // Sender @kicker and target @target both at PL 50; kick level is also 50.
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 100, 0, "@kicker:example.org", 50);
        auto const target_member_json = make_member_event("@target:example.org", "@target:example.org", "join");

        auto parsed_create = merovingian::canonicaljson::parse_lossless(create_json);
        auto parsed_pl = merovingian::canonicaljson::parse_lossless(pl_json);
        auto parsed_target_member = merovingian::canonicaljson::parse_lossless(target_member_json);
        REQUIRE(parsed_create.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_pl.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_target_member.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parsed_create.value;
        auth_events.power_levels = parsed_pl.value;
        auth_events.target_member = parsed_target_member.value;

        // The kick event: @kicker sets @target's membership to leave.
        auto const kick_json = make_member_event("@kicker:example.org", "@target:example.org", "leave");
        auto const parsed_kick = merovingian::canonicaljson::parse_lossless(kick_json);
        REQUIRE(parsed_kick.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the kick event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed_kick.value, *policy, auth_events);

            THEN("the kick is rejected — sender PL must STRICTLY exceed target PL")
            {
                // Spec MUST: to kick, sender's power level must be strictly greater than
                // the target's current power level. Equal levels are not sufficient.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ban power-level comparison: sender PL must STRICTLY exceed target PL.
// Spec: Matrix Server-Server API v1.19 — Authorization Rules, Step 5
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
// ---------------------------------------------------------------------------

SCENARIO("Auth rules reject a ban when the sender's power level equals the target's",
         "[events][auth][membership][ban][conformance]")
{
    GIVEN("a room where the banner and target both hold power level 50")
    {
        auto const create_json = make_create_event("@alice:example.org");
        // @banner at PL 50; target @victim also at PL 50; ban level 50.
        auto const pl_json =
            make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 100, 0, "@banner:example.org", 50);
        auto const target_member_json = make_member_event("@victim:example.org", "@victim:example.org", "join");

        auto parsed_create = merovingian::canonicaljson::parse_lossless(create_json);
        auto parsed_pl = merovingian::canonicaljson::parse_lossless(pl_json);
        auto parsed_target_member = merovingian::canonicaljson::parse_lossless(target_member_json);
        REQUIRE(parsed_create.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_pl.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(parsed_target_member.error == merovingian::canonicaljson::ParseError::none);

        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parsed_create.value;
        auth_events.power_levels = parsed_pl.value;
        auth_events.target_member = parsed_target_member.value;

        // The ban event: @banner sets @victim's membership to ban.
        auto const ban_json = make_member_event("@banner:example.org", "@victim:example.org", "ban");
        auto const parsed_ban = merovingian::canonicaljson::parse_lossless(ban_json);
        REQUIRE(parsed_ban.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the ban event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed_ban.value, *policy, auth_events);

            THEN("the ban is rejected — sender PL must STRICTLY exceed target PL")
            {
                // Spec MUST: to ban, sender's power level must be strictly greater than
                // the target's current power level. Equal levels are not sufficient.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// --- third-party invite auth (rule 4.3.1) --------------------------------------
// Spec: Matrix rooms/v11.md Authorization rules for m.room.member, rule 4.3.1
// URL: ../../docs/matrix-v1.19-spec/rooms/v11.md#authorization-rules
//
// "If content has a third_party_invite property" is a fully self-contained
// decision tree for invites accepted via a 3PID token, replacing the normal
// invite checks (target-not-joined, sender-joined, invite-power).
SCENARIO("Auth rules allow a third-party invite whose signature matches the invite's public key",
         "[events][auth][membership][third-party-invite][conformance]")
{
    GIVEN("a pending m.room.third_party_invite signed by the identity server's key")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-1");
        auto const public_key_b64 = merovingian::federation::test::pubkey_b64(keypair);
        auto const signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@alice:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event("@alice:example.org", "random8nonce", public_key_b64))
                .value;

        auto const member_json =
            make_third_party_signed_member_event("@alice:example.org", "@bob:example.org", "@alice:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is allowed")
            {
                // Spec MUST: rule 4.3.1.7 — a signature in "signed" matches a public
                // key carried by the m.room.third_party_invite event.
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_step == "6");
            }
        }
    }

    GIVEN("a pending m.room.third_party_invite whose public key is only in content.public_keys")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-2");
        auto const public_key_b64 = merovingian::federation::test::pubkey_b64(keypair);
        auto const signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@alice:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event_with_keys_list("@alice:example.org", "random8nonce", public_key_b64))
                .value;

        auto const member_json =
            make_third_party_signed_member_event("@alice:example.org", "@bob:example.org", "@alice:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is allowed — the matching key is found in content.public_keys")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a third-party invite for a banned target user",
         "[events][auth][membership][third-party-invite][conformance]")
{
    GIVEN("a target user who is already banned from the room")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-3");
        auto const public_key_b64 = merovingian::federation::test::pubkey_b64(keypair);
        auto const signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@alice:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event("@alice:example.org", "random8nonce", public_key_b64))
                .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@bob:example.org", "ban"))
                                        .value;

        auto const member_json =
            make_third_party_signed_member_event("@alice:example.org", "@bob:example.org", "@alice:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected — rule 4.3.1.1 bans take priority over a valid signature")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a third-party invite whose signed mxid does not match state_key",
         "[events][auth][membership][third-party-invite][conformance]")
{
    GIVEN("a signed blob whose mxid names a different user than the event's state_key")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-4");
        auto const public_key_b64 = merovingian::federation::test::pubkey_b64(keypair);
        // Signed for @carol, but the member event's state_key targets @bob.
        auto const signature_b64 = sign_third_party_invite_payload("@carol:example.org", "@alice:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event("@alice:example.org", "random8nonce", public_key_b64))
                .value;

        auto const member_json = make_third_party_signed_member_event(
            "@alice:example.org", "@bob:example.org", /* signed.mxid */ "@carol:example.org", "random8nonce",
            "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected — rule 4.3.1.4 requires signed.mxid == state_key")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a third-party invite with no matching m.room.third_party_invite event",
         "[events][auth][membership][third-party-invite][conformance]")
{
    GIVEN("a token that does not match any m.room.third_party_invite state event in the room")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-5");
        auto const signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@alice:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        // auth_events.third_party_invite deliberately left empty — no matching event.

        auto const member_json =
            make_third_party_signed_member_event("@alice:example.org", "@bob:example.org", "@alice:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected — rule 4.3.1.5 requires a matching m.room.third_party_invite event")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

SCENARIO("Auth rules reject a third-party invite whose sender does not match the invite event's sender",
         "[events][auth][membership][third-party-invite][conformance]")
{
    GIVEN("an m.room.third_party_invite created by @alice but the join event claims sender @mallory")
    {
        auto const keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-6");
        auto const public_key_b64 = merovingian::federation::test::pubkey_b64(keypair);
        auto const signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@mallory:example.org",
                                                                   "random8nonce", keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event("@alice:example.org", "random8nonce", public_key_b64))
                .value;

        auto const member_json =
            make_third_party_signed_member_event("@mallory:example.org", "@bob:example.org", "@mallory:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected — rule 4.3.1.6 requires sender == m.room.third_party_invite sender")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: rooms/v11.md rule 4.3.1.8 — "Otherwise, reject."
// A forged or corrupted signature MUST NOT be accepted merely because every
// other field (mxid, token, sender) lines up correctly.
SCENARIO("Auth rules reject a third-party invite with a forged signature",
         "[events][auth][membership][third-party-invite][security][conformance]")
{
    GIVEN("a signed blob whose signature was produced by the wrong key")
    {
        auto const invite_keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-7-invite-key");
        auto const attacker_keypair = merovingian::federation::test::keypair_from_seed("tpi-seed-7-attacker-key");
        auto const invite_public_key_b64 = merovingian::federation::test::pubkey_b64(invite_keypair);
        // Signed with the ATTACKER's key, not the key published on the invite.
        auto const forged_signature_b64 = sign_third_party_invite_payload("@bob:example.org", "@alice:example.org",
                                                                          "random8nonce", attacker_keypair.secret_key);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@alice:example.org")).value;
        auth_events.third_party_invite =
            merovingian::canonicaljson::parse_lossless(
                make_third_party_invite_event("@alice:example.org", "random8nonce", invite_public_key_b64))
                .value;

        auto const member_json =
            make_third_party_signed_member_event("@alice:example.org", "@bob:example.org", "@alice:example.org",
                                                 "random8nonce", "example.org", "ed25519:0", forged_signature_b64);
        auto const parsed = merovingian::canonicaljson::parse_lossless(member_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the third-party invite join event is authorized")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the invite is rejected — the signature does not verify against the invite's public key")
            {
                // Security-critical: do NOT weaken this to accept mismatched keys.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: rooms/v11.md Authorization rules, rule 6 — "If type is
// m.room.third_party_invite: allow if and only if sender's current power
// level is greater than or equal to the invite level." This is distinct from
// the generic state_default gate (step 13/rule 7) that other state events use.
SCENARIO("Auth rules gate m.room.third_party_invite creation on invite power, not state_default",
         "[events][auth][third-party-invite][power-levels][conformance]")
{
    GIVEN("a room where invite power (50) is lower than state_default (100)")
    {
        auto const tpi_json = make_third_party_invite_event("@alice:example.org", "random8nonce", "abc123");
        auto const parsed = merovingian::canonicaljson::parse_lossless(tpi_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 100, 0, "@alice:example.org", 50))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("@alice (power 50, below state_default 100 but at invite level 50) creates the invite")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is allowed — invite power, not state_default, gates this event type")
            {
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_step == "6");
            }
        }
    }

    GIVEN("a room where @alice's power is below the invite level")
    {
        auto const tpi_json = make_third_party_invite_event("@alice:example.org", "random8nonce", "abc123");
        auto const parsed = merovingian::canonicaljson::parse_lossless(tpi_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("@alice (power 0, below invite level 50) creates the invite")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the event is rejected")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.rule_step == "6");
            }
        }
    }
}

// Spec: rooms/v10.md Authorization rules, rule 6.2 — "If the sender's power
// level is greater than or equal to the ban level, AND the target user's
// power level is less than the sender's power level, allow." A sender who
// merely clears the ban-level bar is not enough: the target's own power must
// also be strictly lower than the sender's. Regression test for #409.
SCENARIO("Auth rules reject a ban when the target's power level is not below the sender's",
         "[events][auth][membership][ban][power-levels][security]")
{
    GIVEN("a room where @alice (power 50) has ban power but @bob is an equal-power moderator")
    {
        auto const ban_json = make_member_event("@alice:example.org", "@bob:example.org", "ban");
        auto const parsed = merovingian::canonicaljson::parse_lossless(ban_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        // Neither @alice nor @bob is the creator, so neither holds infinite power.
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@alice:example.org", 50, 50, 50, 50, 0, 50, 0,
                                              {
                                                  {"@alice:example.org", 50},
                                                  {"@bob:example.org",   50}
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("@alice (power 50, meets ban level) tries to ban @bob (also power 50)")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the ban is rejected — target power is not strictly less than sender power")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: rooms/v10.md Authorization rules, rule 5.4 — the same target-power
// guard applies to kicks (membership=leave targeting another user).
// Regression test for #409.
SCENARIO("Auth rules reject a kick when the target's power level is not below the sender's",
         "[events][auth][membership][kick][power-levels][security]")
{
    GIVEN("a room where @alice (power 50) has kick power but @bob is an equal-power moderator")
    {
        auto const kick_json = make_member_event("@alice:example.org", "@bob:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(kick_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event_users("@alice:example.org", 50, 50, 50, 50, 0, 50, 0,
                                              {
                                                  {"@alice:example.org", 50},
                                                  {"@bob:example.org",   50}
        }))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@bob:example.org", "@bob:example.org", "join"))
                                        .value;

        WHEN("@alice (power 50, meets kick level) tries to kick @bob (also power 50)")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the kick is rejected — target power is not strictly less than sender power")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: rooms/v10.md Authorization rules, rule 5 — "To unban somebody, you
// must have power level greater than or equal to both the kick and ban
// levels, and greater than the target user's power level." A sender who only
// meets the ban level (but not the kick level) MUST NOT be able to unban.
// Regression test for #409.
SCENARIO("Auth rules reject an unban when the sender meets ban level but not kick level",
         "[events][auth][membership][ban][power-levels][security]")
{
    GIVEN("a room where the ban level (0) is lower than the kick level (50) and @bob is banned")
    {
        auto const unban_json = make_member_event("@alice:example.org", "@bob:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(unban_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        // ban_level=0, kick_level=50: @alice (power 10) clears the ban bar but not the kick bar.
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 0, 50, 50, 50, 0, 50, 0, "@alice:example.org", 10))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@bob:example.org", "@bob:example.org", "ban"))
                .value;

        WHEN("@alice (power 10) tries to unban @bob")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the unban is rejected — sender power is below the kick level")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: rooms/v10.md Authorization rules, rule 5 — the same rule text as
// above. A sender meeting both the ban and kick level, and outranking the
// (defaulted, power 0) target, MUST be allowed to unban.
SCENARIO("Auth rules allow an unban when the sender meets both ban and kick levels and outranks the target",
         "[events][auth][membership][ban][power-levels]")
{
    GIVEN("a room where @alice meets both the ban and kick levels and @bob is banned at default power")
    {
        auto const unban_json = make_member_event("@alice:example.org", "@bob:example.org", "leave");
        auto const parsed = merovingian::canonicaljson::parse_lossless(unban_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 50, 50, 50, 50, 0, 50, 0, "@alice:example.org", 50))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;
        auth_events.target_member =
            merovingian::canonicaljson::parse_lossless(make_member_event("@bob:example.org", "@bob:example.org", "ban"))
                .value;

        WHEN("@alice (power 50) unbans @bob (default power 0)")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the unban is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

// Spec: server-server-api.md#redactions — "Redaction events are
// authorized...like any other event of that type" (via events_default /
// events["m.room.redaction"]); the `redact` and `ban` power levels play no
// part in authorizing the redaction event itself (they only govern whether
// an already-authorized redaction is *applied* to its target). Regression
// test for #410: with events_default=0 and redact=100, a power-0 sender must
// be allowed to send the redaction event.
SCENARIO("Auth rules authorize m.room.redaction via events_default, not the redact/ban levels",
         "[events][auth][redaction][power-levels][security]")
{
    GIVEN("a room with events_default=0 but redact=100 and @alice at default power 0")
    {
        auto const redaction_json = make_redaction_event("@alice:example.org", "$someevent");
        auto const parsed = merovingian::canonicaljson::parse_lossless(redaction_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        auth_events.power_levels =
            merovingian::canonicaljson::parse_lossless(
                make_power_levels_event("@alice:example.org", 100, 50, 50, 100, 0, 50, 0, "@alice:example.org", 0))
                .value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("@alice (power 0) sends the redaction")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the redaction is allowed — events_default (0) gates it, not redact (100)")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

// Regression test for #410, the mirror case: with events["m.room.redaction"]=100
// and redact=0, a power-60 sender must be REJECTED even though 60 >= redact(0).
// The old code's `sender_power >= redact_level || sender_power >= ban_level`
// check would have allowed this; the fix authorizes via events_default/events
// map only.
SCENARIO("Auth rules reject m.room.redaction when below the events-map level, even if above the redact level",
         "[events][auth][redaction][power-levels][security]")
{
    GIVEN("a room with events[\"m.room.redaction\"]=100, redact=0, ban=0, and @alice at power 60")
    {
        auto const redaction_json = make_redaction_event("@alice:example.org", "$someevent");
        auto const parsed = merovingian::canonicaljson::parse_lossless(redaction_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = merovingian::canonicaljson::parse_lossless(make_create_event("@admin:example.org")).value;
        // make_power_levels_event has no "events" map parameter, so build the JSON
        // directly to set events["m.room.redaction"]=100 alongside redact=0/ban=0.
        auto const power_levels_json =
            std::string{"{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"@alice:example.org\","
                        "\"room_id\":\"!room:example.org\",\"content\":{\"ban\":0,\"invite\":50,\"kick\":50,"
                        "\"redact\":0,\"users_default\":0,\"state_default\":50,\"events_default\":0,"
                        "\"events\":{\"m.room.redaction\":100},\"users\":{\"@alice:example.org\":60}},"
                        "\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
                        "\"hashes\":{\"sha256\":\"hash\"}}"};
        auth_events.power_levels = merovingian::canonicaljson::parse_lossless(power_levels_json).value;
        auth_events.sender_member = merovingian::canonicaljson::parse_lossless(
                                        make_member_event("@alice:example.org", "@alice:example.org", "join"))
                                        .value;

        WHEN("@alice (power 60) sends the redaction")
        {
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(parsed.value, *policy, auth_events);

            THEN("the redaction is rejected — events[\"m.room.redaction\"] (100) gates it, not redact (0)")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}
