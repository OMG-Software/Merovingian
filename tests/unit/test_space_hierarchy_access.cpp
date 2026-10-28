// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Behaviour tests for who may see which room in a space hierarchy.
//
// Coverage:
//   - suggested_only narrows a space's children_state, not just the rooms walked
//   - a restricted child is shown to a user who meets one of its allow conditions
//   - the federation hierarchy answers a restricted room only to a server that has
//     a user joined to an allowed room, and lists what it withholds as inaccessible

#include "../support/json_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/space_hierarchy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace canonicaljson = merovingian::canonicaljson;

namespace
{

// A state event with a deterministic event ID, so a scenario can build a room's
// state in a few lines.
std::uint64_t event_counter{0U};

// A later event for the same (type, state key) replaces the earlier one in the
// room's current state, as a membership change does.
auto add_state_event(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view sender,
                     std::string_view event_type, std::string_view state_key, std::string_view content_json) -> void
{
    auto const event_id = std::string{"$e"} + std::to_string(++event_counter);
    auto const json = std::string{"{\"type\":\""} + std::string{event_type} + "\",\"sender\":\"" + std::string{sender} +
                      "\",\"origin_server_ts\":5000,\"content\":" + std::string{content_json} + "}";
    store.events.push_back({event_id, std::string{room_id}, std::string{sender}, json, 0U, 0U, {}, {}, {}});
    for (auto& state : store.state)
    {
        if (state.room_id == room_id && state.event_type == event_type && state.state_key == state_key)
        {
            state.event_id = event_id;
            return;
        }
    }
    store.state.push_back({std::string{room_id}, std::string{event_type}, std::string{state_key}, event_id});
}

auto add_room(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view creator,
              std::string_view create_content, std::string_view join_rules_content) -> void
{
    store.rooms.push_back({std::string{room_id}, std::string{creator}});
    add_state_event(store, room_id, creator, "m.room.create", "", create_content);
    add_state_event(store, room_id, creator, "m.room.join_rules", "", join_rules_content);
    add_state_event(store, room_id, creator, "m.room.member", creator, R"({"membership":"join"})");
}

auto add_member(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view user_id,
                std::string_view membership = "join") -> void
{
    add_state_event(store, room_id, user_id, "m.room.member", user_id,
                    std::string{R"({"membership":")"} + std::string{membership} + R"("})");
}

auto add_child_link(merovingian::database::PersistentStore& store, std::string_view parent, std::string_view child,
                    bool suggested) -> void
{
    add_state_event(store, parent, "@alice:example.org", "m.space.child", child,
                    suggested ? R"({"via":["example.org"],"suggested":true})"
                              : R"({"via":["example.org"],"suggested":false})");
}

[[nodiscard]] auto room_ids_of(merovingian::homeserver::SpaceHierarchyResult const& result) -> std::vector<std::string>
{
    REQUIRE(result.status == 200U);
    auto const body = merovingian::tests::parse_object(result.body);
    auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto ids = std::vector<std::string>{};
    for (auto const& room : *rooms)
    {
        auto const* object = std::get_if<canonicaljson::Object>(&room.storage());
        REQUIRE(object != nullptr);
        ids.push_back(*merovingian::tests::string_member(*object, "room_id"));
    }
    return ids;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string_view wanted) -> bool
{
    return std::ranges::find(ids, wanted) != ids.end();
}

constexpr auto restricted_to_space = std::string_view{
    R"({"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":"!space:example.org"}]})"};

// A public space with one restricted child that allows members of the space.
// @alice is in the space, @bob is not, @carol is in an unrelated room only.
[[nodiscard]] auto setup_restricted_runtime() -> merovingian::homeserver::HomeserverRuntime
{
    auto runtime = merovingian::homeserver::HomeserverRuntime{};
    auto& store = runtime.database.persistent_store;
    add_room(store, "!space:example.org", "@alice:example.org", R"({"type":"m.space","room_version":"10"})",
             R"({"join_rule":"public"})");
    add_room(store, "!restricted:example.org", "@alice:example.org", R"({"room_version":"10"})", restricted_to_space);
    add_room(store, "!unrelated:example.org", "@carol:example.org", R"({"room_version":"10"})",
             R"({"join_rule":"public"})");
    add_child_link(store, "!space:example.org", "!restricted:example.org", false);
    return runtime;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidhierarchy
//
// "suggested_only: ... flag to indicate whether or not the server should only consider suggested
// rooms." A room that is not considered is not linked to either: the space's `children_state`
// carries the `m.space.child` events of the suggested children only.
SCENARIO("suggested_only leaves the unsuggested links out of children_state",
         "[homeserver][space-hierarchy][suggested]")
{
    GIVEN("a space with one suggested and one unsuggested child")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        add_room(store, "!space:example.org", "@alice:example.org", R"({"type":"m.space"})",
                 R"({"join_rule":"public"})");
        add_room(store, "!liked:example.org", "@alice:example.org", "{}", R"({"join_rule":"public"})");
        add_room(store, "!plain:example.org", "@alice:example.org", "{}", R"({"join_rule":"public"})");
        add_child_link(store, "!space:example.org", "!liked:example.org", true);
        add_child_link(store, "!space:example.org", "!plain:example.org", false);

        WHEN("alice asks for the suggested rooms only")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            request.suggested_only = true;
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);

            THEN("the space lists only its suggested child as a child")
            {
                REQUIRE(result.status == 200U);
                auto const body = merovingian::tests::parse_object(result.body);
                auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE_FALSE(rooms->empty());
                auto const* root = std::get_if<canonicaljson::Object>(&rooms->at(0).storage());
                REQUIRE(root != nullptr);
                auto const* children_state = merovingian::tests::object_member_as_array(*root, "children_state");
                REQUIRE(children_state != nullptr);
                REQUIRE(children_state->size() == 1U);
                auto const* link = std::get_if<canonicaljson::Object>(&children_state->at(0).storage());
                REQUIRE(link != nullptr);
                REQUIRE(*merovingian::tests::string_member(*link, "state_key") == "!liked:example.org");
            }
        }

        WHEN("alice asks for every room")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);

            THEN("the space still lists both children")
            {
                REQUIRE(result.status == 200U);
                auto const body = merovingian::tests::parse_object(result.body);
                auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* root = std::get_if<canonicaljson::Object>(&rooms->at(0).storage());
                REQUIRE(root != nullptr);
                auto const* children_state = merovingian::tests::object_member_as_array(*root, "children_state");
                REQUIRE(children_state != nullptr);
                REQUIRE(children_state->size() == 2U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /_matrix/client/v1/rooms/{roomId}/hierarchy, 200 `rooms`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidhierarchy
//
// "The server should return any rooms where at least one of the following conditions is true: ...
// The room's join rules are set to `restricted`, provided the user meets one of the specified
// conditions."
SCENARIO("a restricted child appears only for a user who meets one of its conditions",
         "[homeserver][space-hierarchy][restricted]")
{
    GIVEN("a space whose child is restricted to members of the space")
    {
        auto runtime = setup_restricted_runtime();
        auto& store = runtime.database.persistent_store;

        WHEN("bob, who is not in the space, asks for the hierarchy")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const ids = room_ids_of(
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@bob:example.org", request));

            THEN("he sees the space and not the restricted room")
            {
                REQUIRE(contains(ids, "!space:example.org"));
                REQUIRE_FALSE(contains(ids, "!restricted:example.org"));
            }
        }

        WHEN("carol, who is in an unrelated room only, asks for the hierarchy")
        {
            add_member(store, "!unrelated:example.org", "@carol:example.org");
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const ids = room_ids_of(
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@carol:example.org", request));

            THEN("she does not see the restricted room")
            {
                REQUIRE_FALSE(contains(ids, "!restricted:example.org"));
            }
        }

        WHEN("alice, who is joined to the space, asks for the hierarchy")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const ids = room_ids_of(
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request));

            THEN("she sees the space and the restricted room")
            {
                REQUIRE(contains(ids, "!space:example.org"));
                REQUIRE(contains(ids, "!restricted:example.org"));
            }
        }

        WHEN("bob joins the space")
        {
            add_member(store, "!space:example.org", "@bob:example.org");
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const ids = room_ids_of(
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@bob:example.org", request));

            THEN("the restricted room appears for him")
            {
                REQUIRE(contains(ids, "!restricted:example.org"));
            }
        }

        WHEN("bob only has an invite to the space")
        {
            add_member(store, "!space:example.org", "@bob:example.org", "invite");
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const ids = room_ids_of(
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@bob:example.org", request));

            THEN("the restricted room stays hidden, as an invite is not membership")
            {
                REQUIRE_FALSE(contains(ids, "!restricted:example.org"));
            }
        }

        WHEN("bob asks for the hierarchy of the restricted room itself")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!restricted:example.org"};
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@bob:example.org", request);

            THEN("he is refused, and alice is not")
            {
                REQUIRE(result.status == 403U);
                auto const allowed =
                    merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
                REQUIRE(allowed.status == 200U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/hierarchy/{roomId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1hierarchyroomid
//
// "all the space-room's children the requesting server could feasibly peek/join are returned";
// `children`: "Rooms which the requesting server cannot peek/join will be excluded";
// `inaccessible_children` (required): "The list of room IDs the requesting server doesn't have a
// viable way to peek/join. Rooms which the responding server cannot provide details on will be
// outright excluded from the response instead."
SCENARIO("the federation hierarchy answers a restricted room only to a server with a member of an allowed room",
         "[homeserver][space-hierarchy][federation][restricted]")
{
    GIVEN("a space with a restricted child and a child this server does not hold")
    {
        auto runtime = setup_restricted_runtime();
        auto& store = runtime.database.persistent_store;
        add_member(store, "!space:example.org", "@carol:remote.example.org");
        add_state_event(store, "!space:example.org", "@alice:example.org", "m.space.child", "!ghost:example.org",
                        R"({"via":["example.org"]})");

        WHEN("a server with a user in the space asks for the space")
        {
            auto const body = merovingian::homeserver::build_federation_space_hierarchy_response(
                runtime, "!space:example.org", false, "remote.example.org");
            REQUIRE_FALSE(body.empty());
            auto const response = merovingian::tests::parse_object(body);
            auto const* children = merovingian::tests::object_member_as_array(response, "children");
            auto const* inaccessible = merovingian::tests::object_member_as_array(response, "inaccessible_children");

            THEN("the restricted child is returned and nothing is listed as inaccessible")
            {
                REQUIRE(children != nullptr);
                REQUIRE(children->size() == 1U);
                auto const* child = std::get_if<canonicaljson::Object>(&children->at(0).storage());
                REQUIRE(child != nullptr);
                REQUIRE(*merovingian::tests::string_member(*child, "room_id") == "!restricted:example.org");
                // Spec: allowed_room_ids: "the room IDs which are specified by the join rules".
                REQUIRE(merovingian::tests::object_member_as_array(*child, "allowed_room_ids") != nullptr);
                REQUIRE(inaccessible != nullptr);
                REQUIRE(inaccessible->empty());
            }
        }

        WHEN("a server with no user in the space asks for the space")
        {
            auto const body = merovingian::homeserver::build_federation_space_hierarchy_response(
                runtime, "!space:example.org", false, "stranger.example.org");
            REQUIRE_FALSE(body.empty());
            auto const response = merovingian::tests::parse_object(body);
            auto const* children = merovingian::tests::object_member_as_array(response, "children");
            auto const* inaccessible = merovingian::tests::object_member_as_array(response, "inaccessible_children");

            THEN("the restricted child is withheld and named as inaccessible")
            {
                REQUIRE(children != nullptr);
                REQUIRE(children->empty());
                REQUIRE(inaccessible != nullptr);
                REQUIRE(inaccessible->size() == 1U);
                auto const* id = std::get_if<std::string>(&inaccessible->at(0).storage());
                REQUIRE(id != nullptr);
                REQUIRE(*id == "!restricted:example.org");
            }

            AND_THEN("a room this server does not hold is in neither list")
            {
                // Spec: "Rooms which the responding server cannot provide details on will be outright
                // excluded from the response instead." (children_state still names the link.)
                REQUIRE(inaccessible != nullptr);
                for (auto const& id : *inaccessible)
                {
                    REQUIRE(*std::get_if<std::string>(&id.storage()) != "!ghost:example.org");
                }
            }
        }

        WHEN("each server asks for the restricted room itself")
        {
            auto const for_member = merovingian::homeserver::build_federation_space_hierarchy_response(
                runtime, "!restricted:example.org", false, "remote.example.org");
            auto const for_stranger = merovingian::homeserver::build_federation_space_hierarchy_response(
                runtime, "!restricted:example.org", false, "stranger.example.org");

            THEN("only the server with a user in an allowed room is answered")
            {
                REQUIRE_FALSE(for_member.empty());
                REQUIRE(for_stranger.empty());
            }
        }

        WHEN("the only user of a server in the space has left")
        {
            add_member(store, "!space:example.org", "@carol:remote.example.org", "leave");
            auto const body = merovingian::homeserver::build_federation_space_hierarchy_response(
                runtime, "!restricted:example.org", false, "remote.example.org");

            THEN("the restricted room is no longer served to that server")
            {
                REQUIRE(body.empty());
            }
        }
    }
}
