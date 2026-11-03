// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX PROFILE PROPAGATION CONFORMANCE TESTS                     |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers "Events on Change of Profile Information": a display name or     |
// |  avatar change sends an m.room.member join event to every joined room,   |
// |  and membership events this server emits for its own users carry the     |
// |  display name and avatar URL.                                            |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/periodic_job.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
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

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart)
    -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    // Fixture: registration must succeed before this helper can log in the user.
    REQUIRE(reg.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEVICE1\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    // Fixture: login must succeed so the profile request uses an authenticated session.
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the successful login response must provide the token used by later requests.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_public_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"});
    // Fixture: room creation must succeed before room propagation is exercised.
    REQUIRE(create.response.status == 200U);
    auto const body = parse_object(create.response.body);
    auto const* room_id = string_member(body, "room_id");
    // Fixture: the successful room-creation response must provide a room ID.
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto join(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token, std::string const& room_id)
    -> void
{
    auto const joined = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/join/" + room_id, token, "{}"});
    // Fixture: the second user must join before room membership propagation is exercised.
    REQUIRE(joined.response.status == 200U);
}

auto put_profile_field(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                       std::string const& user_id, std::string const& field, std::string const& value) -> void
{
    auto const put = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"PUT", "/_matrix/client/v3/profile/" + user_id + "/" + field, token, "{\"" + field + "\":\"" + value + "\"}"});
    // Fixture: each profile field update in these scenarios must succeed.
    REQUIRE(put.response.status == 200U);
}

// The content of the user's current m.room.member state event in the room.
[[nodiscard]] auto member_content(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                  std::string const& room_id, std::string const& user_id)
    -> merovingian::canonicaljson::Object
{
    auto const state = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + user_id, token, {}});
    // Fixture: the caller must be able to read the room member state used by these assertions.
    REQUIRE(state.response.status == 200U);
    return parse_object(state.response.body);
}

// Number of m.room.member events for `user_id` in the room's timeline of an
// initial /sync by `token`, and the display name the last one carries.
struct TimelineMembership final
{
    std::size_t count{0U};
    std::string last_displayname{};
};

[[nodiscard]] auto timeline_membership(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                       std::string const& room_id, std::string const& user_id) -> TimelineMembership
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    // Fixture: the initial sync must succeed before inspecting its membership timeline.
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    // Fixture: a successful sync response includes the rooms object.
    REQUIRE(rooms != nullptr);
    auto const* joined = object_member_as_object(*rooms, "join");
    // Fixture: the joined-room section is needed to inspect the requested room.
    REQUIRE(joined != nullptr);
    auto const* room = object_member_as_object(*joined, room_id);
    // Fixture: the requested joined room must appear in the sync response.
    REQUIRE(room != nullptr);
    auto const* timeline = object_member_as_object(*room, "timeline");
    // Fixture: each joined-room sync response includes a timeline object.
    REQUIRE(timeline != nullptr);
    auto const* events = object_member_as_array(*timeline, "events");
    // Fixture: the room timeline must expose its events array.
    REQUIRE(events != nullptr);

    auto result = TimelineMembership{};
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        if (event == nullptr)
        {
            continue;
        }
        auto const* type = string_member(*event, "type");
        auto const* state_key = string_member(*event, "state_key");
        if (type == nullptr || *type != "m.room.member" || state_key == nullptr || *state_key != user_id)
        {
            continue;
        }
        ++result.count;
        auto const* content = object_member_as_object(*event, "content");
        auto const* displayname = content != nullptr ? string_member(*content, "displayname") : nullptr;
        result.last_displayname = displayname != nullptr ? *displayname : std::string{};
    }
    return result;
}

[[nodiscard]] auto next_batch_of(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    // Fixture: the initial sync must succeed before its token is used as a baseline.
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* next_batch = string_member(body, "next_batch");
    // Fixture: a successful sync response must provide the next_batch baseline.
    REQUIRE(next_batch != nullptr);
    return *next_batch;
}

// The content of the last m.presence event from `sender` in an incremental /sync since `since`,
// or an empty object when there is none.
[[nodiscard]] auto presence_since(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                  std::string const& since, std::string const& sender)
    -> merovingian::canonicaljson::Object
{
    auto const sync = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/sync?timeout=0&since=" + since, token, {}});
    // Fixture: the incremental sync must succeed before presence events are inspected.
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* presence = object_member_as_object(body, "presence");
    auto const* events = presence != nullptr ? object_member_as_array(*presence, "events") : nullptr;
    auto result = merovingian::canonicaljson::Object{};
    if (events == nullptr)
    {
        return result;
    }
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* type = event != nullptr ? string_member(*event, "type") : nullptr;
        auto const* event_sender = event != nullptr ? string_member(*event, "sender") : nullptr;
        if (type == nullptr || *type != "m.presence" || event_sender == nullptr || *event_sender != sender)
        {
            continue;
        }
        auto const* content = object_member_as_object(*event, "content");
        if (content != nullptr)
        {
            result = *content;
        }
    }
    return result;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information" and
// PUT /_matrix/client/v3/profile/{userId}/{keyName}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// The PUT answers 200 "The profile field was set." (its other responses are 400, 403 and 429).
// Propagation follows the change; a room or presence write that fails does not unset the field.
SCENARIO("a profile change succeeds when propagation cannot complete, and an identical update repairs it",
         "[conformance][client-server][profile][profile-propagation][profile-propagation-failure]")
{
    GIVEN("Alice belongs to two rooms and one propagation write will fail")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const first_room = create_public_room(started.runtime, alice);
        auto const second_room = create_public_room(started.runtime, alice);
        auto const field = std::string{GENERATE("displayname", "avatar_url")};
        auto const value =
            field == "displayname" ? std::string{"Alice Liddell"} : std::string{"mxc://example.org/alice"};
        auto const statement = GENERATE("insert_event", "upsert_presence");
        merovingian::database::force_persist_failure_for_statement(started.runtime.homeserver.database.persistent_store,
                                                                   statement);
        auto const request =
            merovingian::homeserver::LocalHttpRequest{"PUT", "/_matrix/client/v3/profile/@alice:example.org/" + field,
                                                      alice, "{\"" + field + "\":\"" + value + "\"}"};

        WHEN("Alice changes her profile while propagation cannot complete")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(started.runtime, request);

            THEN("the field is set and reported as set, and retrying completes without duplicate joins")
            {
                // Spec MUST: 200 "The profile field was set." The field is stored before propagation starts.
                REQUIRE(first.response.status == 200U);
                auto const profile = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/profile/@alice:example.org", alice, {}});
                // Fixture: the profile lookup must succeed before its fields are inspected.
                REQUIRE(profile.response.status == 200U);
                auto const profile_body = parse_object(profile.response.body);
                auto const* stored = string_member(profile_body, field);
                // Spec MUST: the profile returns the field the 200 said was set.
                REQUIRE(stored != nullptr);
                // Spec MUST: the profile returns the value the 200 said was set.
                REQUIRE(*stored == value);
                auto const retry = merovingian::homeserver::handle_client_server_request(started.runtime, request);
                // Project policy: retrying the identical request after storage recovers completes successfully.
                REQUIRE(retry.response.status == 200U);
                for (auto const& room_id : {first_room, second_room})
                {
                    auto const content = member_content(started.runtime, alice, room_id, "@alice:example.org");
                    auto const* actual = string_member(content, field);
                    // Spec SHOULD: membership propagation carries the changed displayname or avatar_url.
                    REQUIRE(actual != nullptr);
                    // Spec SHOULD: the changed profile value reaches every room Alice is a member of.
                    REQUIRE(*actual == value);
                    auto const seen = timeline_membership(started.runtime, alice, room_id, "@alice:example.org");
                    // Project policy: retry must not duplicate the earlier membership event; the spec only recommends
                    // profile propagation.
                    REQUIRE(seen.count == 2U);
                }
            }
        }
    }

    // A stored profile field this server cannot serialise (here an avatar URL holding a byte that
    // is not UTF-8) leaves no membership event to send. The field being set is still set.
    GIVEN("Alice belongs to a room and her stored avatar URL cannot be serialised")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        std::ignore = create_public_room(started.runtime, alice);
        auto& store = started.runtime.homeserver.database.persistent_store;
        // Fixture: a profile row whose avatar URL is not valid UTF-8, as no client request can write.
        REQUIRE(merovingian::database::store_profile(store, {"@alice:example.org", {}, "mxc://example.org/\xff"}));

        WHEN("Alice sets her display name")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/@alice:example.org/displayname", alice,
                                  R"({"displayname":"Alice Liddell"})"});

            THEN("the field is set and reported as set")
            {
                // Spec MUST: 200 "The profile field was set."
                REQUIRE(put.response.status == 200U);
                auto const profile = merovingian::database::find_profile(store, "@alice:example.org");
                // Fixture: the profile row is still held.
                REQUIRE(profile.has_value());
                // Spec MUST: the field the 200 reports as set is stored.
                REQUIRE(profile->displayname == "Alice Liddell");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// "an m.presence presence status update is sent, again containing the new values of the
// displayname and avatar_url keys, in addition to the required presence key containing the
// current presence state of the user. Both of these should be done automatically by the
// homeserver when a user successfully changes their display name or avatar URL fields."
SCENARIO("changing the display name or avatar sends an m.presence update carrying them",
         "[conformance][client-server][profile][profile-propagation][presence]")
{
    GIVEN("Alice and Bob in a room, with Alice online and Bob synced up to date")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        join(started.runtime, bob, room_id);
        auto const online = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/presence/@alice:example.org/status", alice,
                              R"({"presence":"online","status_msg":"baking"})"});
        // Fixture: Alice's online state is needed to verify the current presence value is preserved.
        REQUIRE(online.response.status == 200U);
        auto const since = next_batch_of(started.runtime, bob);

        WHEN("Alice sets her display name")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "displayname", "Alice Liddell");
            auto const content = presence_since(started.runtime, bob, since, "@alice:example.org");

            THEN("Bob receives her presence again, unchanged, now with the new display name")
            {
                auto const* presence = string_member(content, "presence");
                // Spec SHOULD: the propagated presence update contains the required current presence key.
                REQUIRE(presence != nullptr);
                // Fixture: the update preserves Alice's existing presence state.
                REQUIRE(*presence == "online");
                auto const* status_msg = string_member(content, "status_msg");
                // Fixture: the profile update preserves the unrelated status message.
                REQUIRE(status_msg != nullptr);
                // Fixture: the profile update preserves the unrelated status message value.
                REQUIRE(*status_msg == "baking");
                auto const* displayname = string_member(content, "displayname");
                // Spec SHOULD: the presence update includes the changed displayname.
                REQUIRE(displayname != nullptr);
                // Spec SHOULD: the presence update carries the new displayname value.
                REQUIRE(*displayname == "Alice Liddell");
            }
        }

        WHEN("Alice sets her avatar URL")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "avatar_url", "mxc://example.org/alice");
            auto const content = presence_since(started.runtime, bob, since, "@alice:example.org");

            THEN("Bob's presence update carries the new avatar URL")
            {
                auto const* presence = string_member(content, "presence");
                // Spec SHOULD: the propagated presence update contains the required current presence key.
                REQUIRE(presence != nullptr);
                // Fixture: the update preserves Alice's existing presence state.
                REQUIRE(*presence == "online");
                auto const* avatar_url = string_member(content, "avatar_url");
                // Spec SHOULD: the presence update includes the changed avatar_url.
                REQUIRE(avatar_url != nullptr);
                // Spec SHOULD: the presence update carries the new avatar_url value.
                REQUIRE(*avatar_url == "mxc://example.org/alice");
            }
        }
    }

    GIVEN("Alice and Bob in a room, where Alice has never set a presence")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        join(started.runtime, bob, room_id);
        auto const since = next_batch_of(started.runtime, bob);

        WHEN("Alice sets her display name")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "displayname", "Alice Liddell");
            auto const content = presence_since(started.runtime, bob, since, "@alice:example.org");

            THEN("the update still carries the required presence key, as offline, and the display name")
            {
                auto const* presence = string_member(content, "presence");
                // Spec SHOULD: the propagated presence update contains the required current presence key.
                REQUIRE(presence != nullptr);
                // Fixture: Alice has no prior presence event, so this runtime reports her default as offline.
                REQUIRE(*presence == "offline");
                auto const* displayname = string_member(content, "displayname");
                // Spec SHOULD: the presence update includes the changed displayname.
                REQUIRE(displayname != nullptr);
                // Spec SHOULD: the presence update carries the new displayname value.
                REQUIRE(*displayname == "Alice Liddell");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// "an m.room.member event (with a join membership) is sent to every room the user is a member of,
// to update the displayname and avatar_url ... Both of these should be done automatically by the
// homeserver when a user successfully changes their display name or avatar URL fields."
SCENARIO("changing the display name sends a join m.room.member event carrying it to every joined room",
         "[conformance][client-server][profile][profile-propagation]")
{
    GIVEN("Alice and Bob joined to two rooms Alice created")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before room membership propagation is tested.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const first_room = create_public_room(started.runtime, alice);
        auto const second_room = create_public_room(started.runtime, alice);
        join(started.runtime, bob, first_room);
        join(started.runtime, bob, second_room);

        WHEN("Alice sets her display name")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "displayname", "Alice Liddell");

            THEN("her membership in each room is still join and carries the new display name")
            {
                for (auto const& room_id : {first_room, second_room})
                {
                    auto const content = member_content(started.runtime, bob, room_id, "@alice:example.org");
                    auto const* membership = string_member(content, "membership");
                    // Spec SHOULD: profile propagation sends a join membership event to each member room.
                    REQUIRE(membership != nullptr);
                    // Spec SHOULD: the propagated room membership event uses join membership.
                    REQUIRE(*membership == "join");
                    auto const* displayname = string_member(content, "displayname");
                    // Spec SHOULD: the membership event includes the changed displayname.
                    REQUIRE(displayname != nullptr);
                    // Spec SHOULD: the membership event carries the new displayname value.
                    REQUIRE(*displayname == "Alice Liddell");
                }
            }
            THEN("Bob's /sync delivers the membership update in the room timeline")
            {
                auto const seen = timeline_membership(started.runtime, bob, first_room, "@alice:example.org");
                // Spec SHOULD: the profile change adds a membership event to the room timeline.
                REQUIRE(seen.count >= 2U);
                // Spec SHOULD: the new timeline membership event carries the updated displayname.
                REQUIRE(seen.last_displayname == "Alice Liddell");
            }
        }

        WHEN("Alice sets her avatar URL")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "avatar_url", "mxc://example.org/avatar");

            THEN("her membership in each room carries the new avatar URL")
            {
                for (auto const& room_id : {first_room, second_room})
                {
                    auto const content = member_content(started.runtime, bob, room_id, "@alice:example.org");
                    auto const* membership = string_member(content, "membership");
                    // Spec SHOULD: profile propagation sends a join membership event to each member room.
                    REQUIRE(membership != nullptr);
                    // Spec SHOULD: the propagated room membership event uses join membership.
                    REQUIRE(*membership == "join");
                    auto const* avatar_url = string_member(content, "avatar_url");
                    // Spec SHOULD: the membership event includes the changed avatar_url.
                    REQUIRE(avatar_url != nullptr);
                    // Spec SHOULD: the membership event carries the new avatar_url value.
                    REQUIRE(*avatar_url == "mxc://example.org/avatar");
                }
            }
        }

        WHEN("Alice sets a display name and then an avatar URL")
        {
            put_profile_field(started.runtime, alice, "@alice:example.org", "displayname", "Alice Liddell");
            put_profile_field(started.runtime, alice, "@alice:example.org", "avatar_url", "mxc://example.org/avatar");

            THEN("the latest membership event carries both, so neither change undoes the other")
            {
                auto const content = member_content(started.runtime, bob, first_room, "@alice:example.org");
                auto const* displayname = string_member(content, "displayname");
                // Spec SHOULD: the latest membership event retains the changed displayname.
                REQUIRE(displayname != nullptr);
                // Spec SHOULD: the latest membership event carries the new displayname value.
                REQUIRE(*displayname == "Alice Liddell");
                auto const* avatar_url = string_member(content, "avatar_url");
                // Spec SHOULD: the latest membership event retains the changed avatar_url.
                REQUIRE(avatar_url != nullptr);
                // Spec SHOULD: the latest membership event carries the new avatar_url value.
                REQUIRE(*avatar_url == "mxc://example.org/avatar");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// The update goes to "every room the user is a member of": a room the user has left is not one,
// and sending a join there would rejoin them.
SCENARIO("changing the display name leaves rooms the user has left untouched",
         "[conformance][client-server][profile][profile-propagation]")
{
    GIVEN("Bob joined a room of Alice's and then left it")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before room membership is exercised.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        join(started.runtime, bob, room_id);
        auto const left = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob, "{}"});
        // Fixture: Bob's leave must succeed before the post-leave profile change.
        REQUIRE(left.response.status == 200U);

        WHEN("Bob sets his display name")
        {
            put_profile_field(started.runtime, bob, "@bob:example.org", "displayname", "Robert");

            THEN("his membership of that room is still leave")
            {
                auto const content = member_content(started.runtime, alice, room_id, "@bob:example.org");
                auto const* membership = string_member(content, "membership");
                // Spec SHOULD: profile updates target rooms the user is a member of, not a room already left.
                REQUIRE(membership != nullptr);
                // Fixture: the profile change must not undo Bob's earlier leave.
                REQUIRE(*membership == "leave");
            }
        }
    }

    // The server keeps a member list per room beside the room's state; the two can disagree (a
    // state-resolution flip, a fast-join fill that re-adds a departed member). The room's current
    // m.room.member state is what says who is a member, and in a public room a join sent on the word
    // of a stale list would succeed and rejoin the user.
    GIVEN("Bob left a public room of Alice's, but the server's member list still names him")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before room membership is exercised.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        join(started.runtime, bob, room_id);
        auto const left = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob, "{}"});
        // Fixture: Bob's leave must succeed before the member list is made stale.
        REQUIRE(left.response.status == 200U);
        auto& rooms = started.runtime.homeserver.database.rooms;
        auto const room = std::ranges::find_if(rooms, [&](auto const& candidate) {
            return candidate.room_id == room_id;
        });
        // Fixture: the room Alice created must be held in the runtime.
        REQUIRE(room != rooms.end());
        room->members.emplace_back("@bob:example.org");

        WHEN("Bob sets his display name")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/profile/@bob:example.org/displayname", bob, R"({"displayname":"Robert"})"});

            THEN("the field is set and his membership of that room is still leave")
            {
                // Spec MUST: 200 "The profile field was set."
                REQUIRE(put.response.status == 200U);
                auto const content = member_content(started.runtime, alice, room_id, "@bob:example.org");
                auto const* membership = string_member(content, "membership");
                // Spec SHOULD: profile updates target rooms the user is a member of, not a room already left.
                REQUIRE(membership != nullptr);
                // Fixture: the profile change must not rejoin Bob to the room he left.
                REQUIRE(*membership == "leave");
            }
        }
    }

    // The member list can also name a user whose current membership cannot be read from the room's
    // state: one who never joined, or whose member event row is missing or unreadable. None of these
    // shows the user to be a member, so nothing is sent there.
    GIVEN("the server's member list names Bob in a room whose state does not show him joined")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before room membership is exercised.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        auto const shape = std::string{GENERATE("never joined", "member event missing", "member event unreadable")};
        auto& store = started.runtime.homeserver.database.persistent_store;
        if (shape != "never joined")
        {
            join(started.runtime, bob, room_id);
            auto const state = std::ranges::find_if(store.state, [&](auto const& row) {
                return row.room_id == room_id && row.event_type == "m.room.member" &&
                       row.state_key == "@bob:example.org";
            });
            // Fixture: Bob's join must be in the room's current state before it is made unreadable.
            REQUIRE(state != store.state.end());
            auto const event = store.events.find(state->event_id);
            // Fixture: the state row must name a stored event.
            REQUIRE(event != store.events.end());
            if (shape == "member event missing")
            {
                auto const member_event_id = event->event_id;
                REQUIRE(store.events.erase_if([&](auto const& row) {
                    return row.event_id == member_event_id;
                }) == 1U);
            }
            else
            {
                store.events.modify(event, [](auto& row) {
                    row.json = "{";
                });
            }
        }
        else
        {
            auto& rooms = started.runtime.homeserver.database.rooms;
            auto const room = std::ranges::find_if(rooms, [&](auto const& candidate) {
                return candidate.room_id == room_id;
            });
            // Fixture: the room Alice created must be held in the runtime.
            REQUIRE(room != rooms.end());
            room->members.emplace_back("@bob:example.org");
        }
        auto const events_before = store.events.size();

        WHEN("Bob sets his display name")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/profile/@bob:example.org/displayname", bob, R"({"displayname":"Robert"})"});

            THEN("the field is set and no membership event is sent to that room")
            {
                // Spec MUST: 200 "The profile field was set."
                REQUIRE(put.response.status == 200U);
                // Spec SHOULD: the update goes to rooms the user is a member of; state that does not
                // show Bob joined is not such a room.
                REQUIRE(store.events.size() == events_before);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// "when homeservers emit room membership events for their own users, they should include the
// display name and avatar URL fields in these events so that clients already have these details
// to hand, and do not have to perform extra round trips to query it."
SCENARIO("membership events this server emits for its own users carry their profile",
         "[conformance][client-server][profile][profile-propagation]")
{
    GIVEN("Alice and Bob who have both set a display name and an avatar URL")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before its own membership events are inspected.
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime, "alice");
        auto const bob = logged_in_token(started.runtime, "bob");
        put_profile_field(started.runtime, alice, "@alice:example.org", "displayname", "Alice Liddell");
        put_profile_field(started.runtime, alice, "@alice:example.org", "avatar_url", "mxc://example.org/alice");
        put_profile_field(started.runtime, bob, "@bob:example.org", "displayname", "Robert");
        put_profile_field(started.runtime, bob, "@bob:example.org", "avatar_url", "mxc://example.org/bob");

        WHEN("Alice creates a room and Bob joins it")
        {
            auto const room_id = create_public_room(started.runtime, alice);
            join(started.runtime, bob, room_id);

            THEN("Alice's creator membership carries her display name and avatar URL")
            {
                auto const content = member_content(started.runtime, alice, room_id, "@alice:example.org");
                auto const* displayname = string_member(content, "displayname");
                // Spec SHOULD: membership events for the server's own user include the display name.
                REQUIRE(displayname != nullptr);
                // Spec SHOULD: that membership event carries Alice's display name.
                REQUIRE(*displayname == "Alice Liddell");
                auto const* avatar_url = string_member(content, "avatar_url");
                // Spec SHOULD: membership events for the server's own user include the avatar URL.
                REQUIRE(avatar_url != nullptr);
                // Spec SHOULD: that membership event carries Alice's avatar URL.
                REQUIRE(*avatar_url == "mxc://example.org/alice");
            }
            THEN("Bob's join carries his display name and avatar URL")
            {
                auto const content = member_content(started.runtime, alice, room_id, "@bob:example.org");
                auto const* membership = string_member(content, "membership");
                // Spec SHOULD: the new member's propagated room membership event uses join membership.
                REQUIRE(membership != nullptr);
                // Spec SHOULD: the new member's propagated room membership event is a join.
                REQUIRE(*membership == "join");
                auto const* displayname = string_member(content, "displayname");
                // Spec SHOULD: membership events for the server's own user include the display name.
                REQUIRE(displayname != nullptr);
                // Spec SHOULD: Bob's membership event carries his display name.
                REQUIRE(*displayname == "Robert");
                auto const* avatar_url = string_member(content, "avatar_url");
                // Spec SHOULD: membership events for the server's own user include the avatar URL.
                REQUIRE(avatar_url != nullptr);
                // Spec SHOULD: Bob's membership event carries his avatar URL.
                REQUIRE(*avatar_url == "mxc://example.org/bob");
            }
        }
    }
}

namespace
{

// A member event's content field, read from the store so that it works for a user with no session.
[[nodiscard]] auto current_member_field(merovingian::homeserver::ClientServerRuntime const& runtime,
                                        std::string const& room_id, std::string const& user_id, std::string_view field)
    -> std::string
{
    auto const& store = runtime.homeserver.database.persistent_store;
    auto const event_id = merovingian::database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
    // Fixture: every room in these scenarios holds the user's membership.
    REQUIRE(event_id.has_value());
    auto const event = store.events.find(*event_id);
    // Fixture: the current state names a stored event.
    REQUIRE(event != store.events.end());
    auto const body = parse_object(event->json);
    auto const* content = object_member_as_object(body, "content");
    // Fixture: a member event has content.
    REQUIRE(content != nullptr);
    auto const* value = string_member(*content, field);
    return value != nullptr ? *value : std::string{};
}

[[nodiscard]] auto rooms_showing_displayname(merovingian::homeserver::ClientServerRuntime const& runtime,
                                             std::vector<std::string> const& rooms, std::string const& user_id,
                                             std::string const& displayname) -> std::vector<std::string>
{
    auto showing = std::vector<std::string>{};
    std::ranges::copy_if(rooms, std::back_inserter(showing), [&](std::string const& room_id) {
        return current_member_field(runtime, room_id, user_id, "displayname") == displayname;
    });
    return showing;
}

[[nodiscard]] auto rooms_not_showing_displayname(merovingian::homeserver::ClientServerRuntime const& runtime,
                                                 std::vector<std::string> const& rooms, std::string const& user_id,
                                                 std::string const& displayname) -> std::vector<std::string>
{
    auto others = std::vector<std::string>{};
    std::ranges::copy_if(rooms, std::back_inserter(others), [&](std::string const& room_id) {
        return current_member_field(runtime, room_id, user_id, "displayname") != displayname;
    });
    return others;
}

// Runs the job body until nothing is queued. The bound stops a job that makes no progress from hanging the suite.
auto run_job_until_idle(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    for (auto run = std::size_t{0U}; run < std::size_t{100000U}; ++run)
    {
        std::ignore = merovingian::homeserver::propagate_queued_profile(runtime.homeserver);
        if (runtime.homeserver.profile_propagation_pending.empty())
        {
            return;
        }
    }
    FAIL("the profile propagation job made no progress");
}

auto create_rooms(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token, std::size_t count)
    -> std::vector<std::string>
{
    auto rooms = std::vector<std::string>{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        rooms.push_back(create_public_room(runtime, token));
    }
    return rooms;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, "Events on Change of Profile Information"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information
//
// "an m.room.member event (with a join membership) is sent to every room the user is a member of" says what is sent,
// and sets no time by which it must have been. How much of that happens under the runtime lock is this server's own
// rule (F-11, ADR-0353): the work one request holds the lock for does not grow with how many rooms the user has.
SCENARIO("a profile change reaches every room without holding the lock for all of them",
         "[f11][conformance][client-server][profile][profile-propagation]")
{
    GIVEN("Alice is a member of more rooms than one request may send to")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice_token = logged_in_token(runtime, "alice");
        auto const alice = std::string{"@alice:example.org"};
        auto const rooms =
            create_rooms(runtime, alice_token, merovingian::homeserver::profile_propagation_sends_per_request + 8U);

        WHEN("she sets her display name")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");

            THEN("the request sends only its own share, and the rest are queued")
            {
                // Project rule (ADR-0353): the lock is held for a fixed number of rooms.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() ==
                        merovingian::homeserver::profile_propagation_sends_per_request);
                // Project rule (ADR-0353): what the request left is owed by the job.
                REQUIRE(runtime.homeserver.profile_propagation_pending.contains(alice));
            }

            THEN("the job reaches every room, once each")
            {
                run_job_until_idle(runtime);
                // Spec SHOULD: the event is sent to every room the user is a member of.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size());
                for (auto const& room_id : rooms)
                {
                    // Project policy: one membership event for the change, on top of the join.
                    REQUIRE(timeline_membership(runtime, alice_token, room_id, alice).count == 2U);
                }
            }
        }

        WHEN("she changes it again before the job has run")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "First");
            put_profile_field(runtime, alice_token, alice, "displayname", "Second");
            auto const unreached = rooms_not_showing_displayname(runtime, rooms, alice, "Second");
            // Fixture: the second request cannot have reached every room.
            REQUIRE_FALSE(unreached.empty());
            run_job_until_idle(runtime);

            THEN("a room the requests did not reach is sent only the latest profile")
            {
                for (auto const& room_id : unreached)
                {
                    auto const seen = timeline_membership(runtime, alice_token, room_id, alice);
                    // Project policy: repeated changes coalesce, so the older name is never sent.
                    REQUIRE(seen.count == 2U);
                    // Spec SHOULD: the event carries the user's current display name.
                    REQUIRE(seen.last_displayname == "Second");
                }
                // Spec SHOULD: the event is sent to every room the user is a member of.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Second").size() == rooms.size());
            }
        }

        WHEN("she leaves a room the job has not reached yet")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
            auto const unreached = rooms_not_showing_displayname(runtime, rooms, alice, "Alice");
            // Fixture: the request cannot have reached every room.
            REQUIRE_FALSE(unreached.empty());
            auto const& left_room = unreached.front();
            auto const left = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + left_room + "/leave", alice_token, "{}"});
            // Fixture: the leave must succeed before the job runs.
            REQUIRE(left.response.status == 200U);
            run_job_until_idle(runtime);

            THEN("the job does not rejoin her, and the other rooms still get the event")
            {
                // Spec SHOULD: the event goes only to rooms the user is a member of. These rooms are public, so a join
                // sent here would succeed.
                REQUIRE(current_member_field(runtime, left_room, alice, "membership") == "leave");
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size() - 1U);
            }
        }

        WHEN("she logs out before the job has run")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
            auto const logged_out = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/logout", alice_token, "{}"});
            // Fixture: the logout must succeed before the job runs.
            REQUIRE(logged_out.response.status == 200U);
            run_job_until_idle(runtime);

            THEN("the change she made while logged in still reaches every room")
            {
                // Spec SHOULD: logging out does not take back a profile field that was set.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size());
            }
        }

        WHEN("an administrator suspends or locks her before the job has run")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
            auto const unreached = rooms_not_showing_displayname(runtime, rooms, alice, "Alice");
            // Fixture: the request cannot have reached every room.
            REQUIRE_FALSE(unreached.empty());
            auto const locked = GENERATE(false, true);
            auto& users = runtime.homeserver.database.users;
            auto const user = std::ranges::find_if(users, [&](auto const& candidate) {
                return candidate.user_id == alice;
            });
            // Fixture: Alice's account is held in the runtime.
            REQUIRE(user != users.end());
            (locked ? user->locked : user->suspended) = true;
            run_job_until_idle(runtime);

            THEN("no more events are sent as her")
            {
                // Spec SHOULD: "Changing profile data" is among the actions recommended forbidden while suspended.
                REQUIRE(rooms_not_showing_displayname(runtime, rooms, alice, "Alice") == unreached);
            }
        }

        WHEN("a room cannot take the event while the job runs")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
            merovingian::database::force_persist_failure_for_statement(runtime.homeserver.database.persistent_store,
                                                                       "insert_event");
            run_job_until_idle(runtime);

            THEN("the other rooms still get the event, and the next change repairs that one")
            {
                // Project policy (ADR-0182): one room's failure stops only that room.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size() - 1U);
                put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
                run_job_until_idle(runtime);
                // Project policy (ADR-0182): the next change sends to every room not yet carrying the profile.
                REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size());
            }
        }

        WHEN("the job is running on its own thread")
        {
            auto& homeserver = runtime.homeserver;
            auto job = merovingian::homeserver::PeriodicJob{
                "profile-propagation", [&homeserver](merovingian::homeserver::StopFlag const&) {
                    return merovingian::homeserver::propagate_queued_profile(homeserver);
                }};
            {
                auto const guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{homeserver.mutex};
                homeserver.profile_propagation_wake = [&job]() {
                    job.wake();
                };
            }
            // Fixture: the job's thread must start for this scenario to mean anything.
            REQUIRE(job.start());
            auto const stop_job = [&]() {
                {
                    auto const guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{homeserver.mutex};
                    homeserver.profile_propagation_wake = nullptr;
                }
                job.stop();
            };

            AND_WHEN("the server shuts down with work still queued")
            {
                put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
                stop_job();

                THEN("the job stops, and what it left can still be finished")
                {
                    // Project rule (ADR-0353): shutdown abandons the queue; it does not wait for it.
                    REQUIRE_FALSE(job.running());
                    // Spec MUST: the field is set whatever became of the fan-out.
                    REQUIRE(current_member_field(runtime, rooms.front(), alice, "displayname") == "Alice");
                    run_job_until_idle(runtime);
                    REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size());
                }
            }

            AND_WHEN("nothing stops it")
            {
                put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
                auto const give_up = std::chrono::steady_clock::now() + std::chrono::seconds{60};
                auto finished = false;
                while (!finished && std::chrono::steady_clock::now() < give_up)
                {
                    {
                        auto const guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{homeserver.mutex};
                        finished = homeserver.profile_propagation_pending.empty();
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
                stop_job();

                THEN("it reaches every room by itself")
                {
                    // Project rule (ADR-0353): the request's wake is all the job needs.
                    REQUIRE(finished);
                    REQUIRE(rooms_showing_displayname(runtime, rooms, alice, "Alice").size() == rooms.size());
                }
            }

            stop_job();
        }
    }

    GIVEN("the server holds more rooms than one lock hold may walk, ahead of Alice's")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice_token = logged_in_token(runtime, "alice");
        auto const alice = std::string{"@alice:example.org"};
        for (auto index = std::size_t{0U}; index < merovingian::homeserver::profile_propagation_rooms_walked_per_hold;
             ++index)
        {
            auto room = merovingian::homeserver::LocalRoom{};
            room.room_id = "!other" + std::to_string(index) + ":example.org";
            runtime.homeserver.database.rooms.push_back(std::move(room));
        }
        auto const room_id = create_public_room(runtime, alice_token);

        WHEN("she sets her display name")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");

            THEN("the request stops walking, and the job finishes the walk")
            {
                // Project rule (ADR-0353): the walk is bounded per hold too.
                REQUIRE(current_member_field(runtime, room_id, alice, "displayname").empty());
                run_job_until_idle(runtime);
                // Spec SHOULD: the event is sent to every room the user is a member of.
                REQUIRE(current_member_field(runtime, room_id, alice, "displayname") == "Alice");
            }
        }
    }

    GIVEN("Alice is a member of more rooms than one lock hold may read her membership of, all already current")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture: the server must start before profile propagation can be tested.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice_token = logged_in_token(runtime, "alice");
        auto const alice = std::string{"@alice:example.org"};
        auto const rooms = create_rooms(runtime, alice_token,
                                        merovingian::homeserver::profile_propagation_member_events_read_per_hold + 1U);
        put_profile_field(runtime, alice_token, alice, "displayname", "Alice");
        run_job_until_idle(runtime);

        WHEN("she sets the same display name again")
        {
            put_profile_field(runtime, alice_token, alice, "displayname", "Alice");

            THEN("the request stops reading, and finishing the walk sends nothing more")
            {
                // Project rule (ADR-0353): reading a member event is bounded per hold as well as sending one.
                REQUIRE(runtime.homeserver.profile_propagation_pending.contains(alice));
                run_job_until_idle(runtime);
                for (auto const& room_id : rooms)
                {
                    // Project policy (ADR-0182): a room already current gets no duplicate.
                    REQUIRE(timeline_membership(runtime, alice_token, room_id, alice).count == 2U);
                }
            }
        }
    }
}
