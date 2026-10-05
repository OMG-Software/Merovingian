// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!"})"});
    REQUIRE(login.response.status == 200U);
    auto const login_body = merovingian::tests::parse_object(login.response.body);
    auto const* token = merovingian::tests::string_member(login_body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto parse(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto make_create_event(std::string_view version, std::string_view sender,
                                     std::string_view content_creator = {}, std::string_view additional_creator = {},
                                     bool non_federated = false) -> std::string
{
    auto json = std::string{"{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\""} + std::string{sender} +
                "\",\"content\":{";
    auto first = true;
    if (!content_creator.empty())
    {
        json += "\"creator\":\"" + std::string{content_creator} + "\"";
        first = false;
    }
    if (!version.empty())
    {
        if (!first)
        {
            json += ',';
        }
        json += "\"room_version\":\"" + std::string{version} + "\"";
        first = false;
    }
    if (!additional_creator.empty())
    {
        if (!first)
        {
            json += ',';
        }
        json += "\"additional_creators\":[\"" + std::string{additional_creator} + "\"]";
        first = false;
    }
    if (non_federated)
    {
        if (!first)
        {
            json += ',';
        }
        json += "\"m.federate\":false";
    }
    json += "},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_events\":[],"
            "\"hashes\":{\"sha256\":\"hash\"}";
    if (version != "12")
    {
        json += ",\"room_id\":\"!room:example.org\"";
    }
    json += '}';
    return json;
}

[[nodiscard]] auto make_join_event(std::string_view sender, std::string_view room_id,
                                   std::vector<std::string_view> const& prev_events,
                                   std::string_view state_key = {}) -> std::string
{
    auto const target_user = state_key.empty() ? sender : state_key;
    auto json = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + std::string{target_user} +
                "\",\"sender\":\"" + std::string{sender} + "\",\"room_id\":\"" + std::string{room_id} +
                "\",\"content\":{\"membership\":\"join\"},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[";
    for (std::size_t index = 0; index < prev_events.size(); ++index)
    {
        if (index != 0U)
        {
            json += ',';
        }
        json += "\"" + std::string{prev_events[index]} + "\"";
    }
    json += "],\"auth_events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
    return json;
}

[[nodiscard]] auto make_message_event(std::string_view sender) -> std::string
{
    return "{\"type\":\"m.room.message\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"msgtype\":\"m.text\",\"body\":\"hi\"},"
           "\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[\"$other\"],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto make_power_event(std::string_view sender) -> std::string
{
    return "{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{},\"origin_server_ts\":2,\"depth\":1,"
           "\"prev_events\":[\"$other\"],\"auth_events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

} // namespace

// Spec: Matrix Client-Server API v1.19, POST /createRoom; Room Versions 10,
// 11 and 12, create event format.
// URLs: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom
//       ../../docs/matrix-v1.19-spec/rooms/v10.md#event-format
//       ../../docs/matrix-v1.19-spec/rooms/v11.md#event-format
//       ../../docs/matrix-v1.19-spec/rooms/v12.md#event-format
// The legacy creator belongs in v10 content; v11+ derive it from sender and
// must not preserve a client-supplied legacy creator property.
SCENARIO("Local room creation emits creator according to the room version",
         "[security_audit_evt_7][conformance][client-server][rooms][room-v10][room-v11][room-v12]")
{
    GIVEN("a running server and an authenticated creator")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user creates v10, v11 and v12 rooms while supplying a forged legacy creator")
        {
            auto const& store = started.runtime.homeserver.database.persistent_store;
            auto persisted_creators = std::vector<std::pair<std::string, std::optional<std::string>>>{};
            for (auto const* version : {"10", "11", "12"})
            {
                auto const request_body = std::string{"{\"room_version\":\""} + version +
                                          "\",\"creation_content\":{\"creator\":\"@mallory:example.org\"}}";
                auto const response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, request_body});
                REQUIRE(response.response.status == 200U);
                auto const response_body = merovingian::tests::parse_object(response.response.body);
                auto const* room_id = merovingian::tests::string_member(response_body, "room_id");
                REQUIRE(room_id != nullptr);

                auto const state = std::ranges::find_if(store.state, [&](auto const& entry) {
                    return entry.room_id == *room_id && entry.event_type == "m.room.create" && entry.state_key.empty();
                });
                REQUIRE(state != store.state.end());
                auto const create = std::ranges::find_if(store.events, [&](auto const& entry) {
                    return entry.event_id == state->event_id;
                });
                REQUIRE(create != store.events.end());
                auto const create_event = merovingian::tests::parse_object(create->json);
                auto const* sender = merovingian::tests::string_member(create_event, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@alice:example.org");
                auto const* content = merovingian::tests::object_member_as_object(create_event, "content");
                REQUIRE(content != nullptr);
                auto const* creator_value = merovingian::tests::object_member(*content, "creator");
                auto const* creator =
                    creator_value == nullptr ? nullptr : std::get_if<std::string>(&creator_value->storage());
                auto creator_value_opt =
                    creator == nullptr ? std::optional<std::string>{} : std::optional<std::string>{*creator};
                persisted_creators.emplace_back(version, creator_value_opt);
                REQUIRE((creator_value == nullptr || creator != nullptr));
            }

            THEN("v10 persists the authenticated creator and v11/v12 omit the legacy property")
            {
                REQUIRE(persisted_creators.size() == 3U);
                REQUIRE(persisted_creators[0].first == "10");
                REQUIRE(persisted_creators[0].second == std::optional<std::string>{"@alice:example.org"});
                REQUIRE(persisted_creators[1].first == "11");
                REQUIRE_FALSE(persisted_creators[1].second.has_value());
                REQUIRE(persisted_creators[2].first == "12");
                REQUIRE_FALSE(persisted_creators[2].second.has_value());
            }
        }
    }
}

// Spec: Matrix Room Version 10, Authorization rules, rule 4.3.1.1.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md#authorization-rules
// The initial join is keyed by the legacy create event's content.creator.
SCENARIO("Room v10 initial creator join uses content.creator",
         "[security_audit_evt_7][events][auth][conformance][room-v10]")
{
    GIVEN("a v10 create event whose sender differs from the legacy content.creator")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parse(make_create_event("10", "@other:example.org", "@alice:example.org"));
        auth_events.create_event_id = "$create";
        auto const join = parse(make_join_event("@alice:example.org", "!room:example.org", {"$create"}));

        WHEN("the legacy creator performs the first join from the sole create event")
        {
            auto const decision = merovingian::events::authorize_event_against_auth_events(join, *policy, auth_events);

            THEN("the join is allowed and the sender field does not replace the v10 creator")
            {
                REQUIRE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Version 10, Authorization rules, rule 4.3.1.1.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md#authorization-rules
// A missing legacy creator must not be replaced by the event sender.
SCENARIO("Room v10 does not infer a missing legacy creator from the create sender",
         "[security_audit_evt_7][events][auth][conformance][room-v10]")
{
    GIVEN("a v10 create event with no content.creator")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto const create = parse(make_create_event("10", "@alice:example.org"));
        auto const empty_power = merovingian::canonicaljson::Value{};

        WHEN("the sender's effective default power is calculated")
        {
            auto const power =
                merovingian::events::effective_sender_power(empty_power, "@alice:example.org", create, *policy);

            THEN("the absent content.creator grants no legacy creator power")
            {
                REQUIRE(power == 0);
            }
        }
    }
}

// Spec: Matrix Room Version 11, Authorization rules, rule 4.3.1.1; Event format.
// URL: ../../docs/matrix-v1.19-spec/rooms/v11.md#authorization-rules
// Room v11 removes content.creator; the create event sender is the creator.
SCENARIO("Room v11 creator identity comes only from the create event sender",
         "[security_audit_evt_7][events][auth][conformance][room-v11]")
{
    GIVEN("a v11 create event with a malicious legacy content.creator value")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto const create = parse(make_create_event("11", "@alice:example.org", "@mallory:example.org"));
        auto const empty_power = merovingian::canonicaljson::Value{};

        WHEN("creator power is evaluated for the create sender and the untrusted content.creator")
        {
            auto const sender_power =
                merovingian::events::effective_sender_power(empty_power, "@alice:example.org", create, *policy);
            auto const forged_power =
                merovingian::events::effective_sender_power(empty_power, "@mallory:example.org", create, *policy);

            THEN("only the sender receives the v11 creator power")
            {
                REQUIRE(sender_power == 100);
                REQUIRE(forged_power == 0);
            }
        }
    }
}

// Spec: Matrix Room Version 12, Authorization rules, creator power and rule 4.3.1.1.
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md#authorization-rules
// v12 grants infinite power to create.sender and content.additional_creators.
SCENARIO("Room v12 privileges the create sender and additional creators only",
         "[security_audit_evt_7][events][auth][conformance][room-v12]")
{
    GIVEN("a v12 create event with one additional creator and a conflicting legacy creator field")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const create =
            parse(make_create_event("12", "@alice:example.org", "@mallory:example.org", "@bob:example.org"));
        auto const empty_power = merovingian::canonicaljson::Value{};

        WHEN("the effective power of all three users is evaluated")
        {
            auto const sender_power =
                merovingian::events::effective_sender_power(empty_power, "@alice:example.org", create, *policy);
            auto const additional_power =
                merovingian::events::effective_sender_power(empty_power, "@bob:example.org", create, *policy);
            auto const forged_power =
                merovingian::events::effective_sender_power(empty_power, "@mallory:example.org", create, *policy);

            THEN("the sender and listed additional creator have infinite power, and the forged value has none")
            {
                REQUIRE(sender_power == std::numeric_limits<std::int64_t>::max());
                REQUIRE(additional_power == std::numeric_limits<std::int64_t>::max());
                REQUIRE(forged_power == 0);
            }
        }
    }
}

// Spec: Matrix Room Versions 10, 11 and 12, Authorization rules, member join rule 1.
// URLs: ../../docs/matrix-v1.19-spec/rooms/v10.md#authorization-rules
//       ../../docs/matrix-v1.19-spec/rooms/v11.md#authorization-rules
//       ../../docs/matrix-v1.19-spec/rooms/v12.md#authorization-rules
// The creator bootstrap applies only when the sole prev_event is the create event.
SCENARIO("Creator bootstrap join requires exactly the authoritative create prev_event",
         "[security_audit_evt_7][events][auth][conformance][membership][room-v11]")
{
    GIVEN("a v11 create event whose sender is the creator")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parse(make_create_event("11", "@alice:example.org", "@mallory:example.org"));
        auth_events.create_event_id = "$create";

        WHEN("the creator's join has the create event as its sole predecessor")
        {
            auto const first_join = parse(make_join_event("@alice:example.org", "!room:example.org", {"$create"}));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(first_join, *policy, auth_events);

            THEN("the create sender's first join is allowed")
            {
                REQUIRE(decision.allowed);
            }
        }

        WHEN("the create sender's state key has that sole predecessor before the sender check")
        {
            auto const first_join =
                parse(make_join_event("@remote:elsewhere.org", "!room:example.org", {"$create"}, "@alice:example.org"));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(first_join, *policy, auth_events);

            THEN("the room-version bootstrap rule allows the event at its specified rule position")
            {
                REQUIRE(decision.allowed);
            }
        }

        WHEN("the creator's join has a different sole predecessor")
        {
            auto const wrong_prev = parse(make_join_event("@alice:example.org", "!room:example.org", {"$other"}));
            auto const wrong_decision =
                merovingian::events::authorize_event_against_auth_events(wrong_prev, *policy, auth_events);

            THEN("the join is rejected")
            {
                REQUIRE_FALSE(wrong_decision.allowed);
            }
        }

        WHEN("the creator's join has the create event and another predecessor")
        {
            auto const multiple_prev =
                parse(make_join_event("@alice:example.org", "!room:example.org", {"$create", "$other"}));
            auto const multiple_decision =
                merovingian::events::authorize_event_against_auth_events(multiple_prev, *policy, auth_events);

            THEN("the join is rejected")
            {
                REQUIRE_FALSE(multiple_decision.allowed);
            }
        }

        WHEN("the create event ID is unavailable to the authorization map")
        {
            auth_events.create_event_id.clear();
            auto const first_join = parse(make_join_event("@alice:example.org", "!room:example.org", {"$create"}));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(first_join, *policy, auth_events);

            THEN("bootstrap fails closed")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Version 12, Authorization rules, creator bootstrap rule.
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md#authorization-rules
// The v12 create event ID is derived from the room ID; additional creators do not receive bootstrap membership.
SCENARIO("Room v12 bootstrap derives the create ID from room_id and only joins the create sender",
         "[security_audit_evt_7][events][auth][conformance][membership][room-v12]")
{
    GIVEN("a v12 create event with a malicious legacy creator and one additional creator")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create =
            parse(make_create_event("12", "@alice:example.org", "@mallory:example.org", "@bob:example.org"));
        auto const room_id = "!roomhash";

        WHEN("the create sender joins with the derived create event ID as sole predecessor")
        {
            auto const first_join = parse(make_join_event("@alice:example.org", room_id, {"$roomhash"}));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(first_join, *policy, auth_events);

            THEN("the create sender's initial join is allowed without a separately stored create ID")
            {
                REQUIRE(decision.allowed);
            }
        }

        WHEN("an additional creator attempts to use the create-sender bootstrap")
        {
            auto const first_join = parse(make_join_event("@bob:example.org", room_id, {"$roomhash"}));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(first_join, *policy, auth_events);

            THEN("the additional creator does not gain implicit membership")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Versions 11 and 12, Authorization rules, steps 10 and 11.
// URLs: ../../docs/matrix-v1.19-spec/rooms/v11.md#authorization-rules
//       ../../docs/matrix-v1.19-spec/rooms/v12.md#authorization-rules
// Create-event authorship alone does not make an unjoined sender a room member.
SCENARIO("An unjoined create sender cannot send or edit power levels through creator fallback",
         "[security_audit_evt_7][events][auth][conformance][membership][room-v11]")
{
    GIVEN("a v11 create event but no membership event for its sender")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);
        auto auth_events = merovingian::events::AuthEventMap{};
        auth_events.create = parse(make_create_event("11", "@alice:example.org"));

        WHEN("the create sender submits an ordinary message")
        {
            auto const message = parse(make_message_event("@alice:example.org"));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(message, *policy, auth_events);

            THEN("the event is rejected because the sender has no joined membership")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }

        WHEN("the create sender submits a power-level event")
        {
            auto const power_event = parse(make_power_event("@alice:example.org"));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(power_event, *policy, auth_events);

            THEN("the event is rejected because the sender has no joined membership")
            {
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Room Version 10 and Room Version 11, Authorization rules, step 3.
// URLs: ../../docs/matrix-v1.19-spec/rooms/v10.md#authorization-rules
//       ../../docs/matrix-v1.19-spec/rooms/v11.md#authorization-rules
// For non-federated rooms, the event sender's domain is compared with the create-event sender's domain.
SCENARIO("Non-federated rooms compare event and create sender domains across creator formats",
         "[security_audit_evt_7][events][auth][conformance][room-v10][room-v11]")
{
    GIVEN("v10 and v11 non-federated create events with misleading content.creator values")
    {
        auto const* v10_policy = merovingian::rooms::find_room_version_policy("10");
        auto const* v11_policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(v10_policy != nullptr);
        REQUIRE(v11_policy != nullptr);
        auto v10_auth = merovingian::events::AuthEventMap{};
        v10_auth.create = parse(make_create_event("10", "@founder:example.org", "@remote:elsewhere.org", {}, true));
        auto v11_auth = merovingian::events::AuthEventMap{};
        v11_auth.create = parse(make_create_event("11", "@founder:example.org", "@remote:elsewhere.org", {}, true));
        auto const remote_join = parse(make_join_event("@remote:elsewhere.org", "!room:example.org", {"$other"}));

        WHEN("a remote user attempts to join either room")
        {
            auto const v10_decision =
                merovingian::events::authorize_event_against_auth_events(remote_join, *v10_policy, v10_auth);
            auto const v11_decision =
                merovingian::events::authorize_event_against_auth_events(remote_join, *v11_policy, v11_auth);

            THEN("both joins are rejected based on the create event sender's domain")
            {
                REQUIRE_FALSE(v10_decision.allowed);
                REQUIRE_FALSE(v11_decision.allowed);
            }
        }
    }
}
