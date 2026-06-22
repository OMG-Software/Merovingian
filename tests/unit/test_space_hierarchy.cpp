// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Behaviour tests for Matrix space hierarchy endpoints.
//
// Coverage:
//   - Client GET /_matrix/client/v1/rooms/{roomId}/hierarchy (module handler)
//   - Federation GET /_matrix/federation/v1/hierarchy/{roomId} response builder
//   - Depth-first traversal, pagination tokens, suggested_only filter, max_depth

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/space_hierarchy.hpp"

#include "../support/json_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace canonicaljson = merovingian::canonicaljson;

namespace
{

[[nodiscard]] auto make_room_json(std::string_view event_type, std::string_view sender,
                                    std::int64_t origin_server_ts, std::string_view content) -> std::string
{
    return std::string{"{\"type\":\""} + std::string{event_type} + "\",\"sender\":\"" + std::string{sender} +
           "\",\"origin_server_ts\":" + std::to_string(origin_server_ts) + ",\"content\":" + std::string{content} + "}";
}

auto append_event(merovingian::database::PersistentStore& store, std::string_view event_id,
                  std::string_view room_id, std::string_view sender, std::int64_t origin_server_ts,
                  std::string_view event_type, std::string_view content_json) -> void
{
    store.events.push_back({
        std::string{event_id},
        std::string{room_id},
        std::string{sender},
        make_room_json(event_type, sender, origin_server_ts, content_json),
        0U,
        0U,
        {},
        {},
        {},
    });
}

auto append_state(merovingian::database::PersistentStore& store, std::string_view room_id,
                  std::string_view event_type, std::string_view state_key, std::string_view event_id) -> void
{
    store.state.push_back({std::string{room_id}, std::string{event_type}, std::string{state_key},
                           std::string{event_id}});
}

[[nodiscard]] auto setup_space_runtime() -> merovingian::homeserver::HomeserverRuntime
{
    auto runtime = merovingian::homeserver::HomeserverRuntime{};
    auto& store = runtime.database.persistent_store;

    // Three rooms: a space with two children, one of which is itself a space.
    store.rooms = {
        {"!space:example.org", "@alice:example.org"},
        {"!child1:example.org", "@alice:example.org"},
        {"!child2:example.org", "@alice:example.org"},
        {"!grandchild:example.org", "@alice:example.org"},
    };

    auto constexpr alice = std::string_view{"@alice:example.org"};

    // Root space.
    append_event(store, "$space-create", "!space:example.org", alice, 1'000,
                 "m.room.create", R"({"type":"m.space"})");
    append_state(store, "!space:example.org", "m.room.create", "", "$space-create");
    append_event(store, "$space-join", "!space:example.org", alice, 1'001,
                 "m.room.member", R"({"membership":"join"})");
    append_state(store, "!space:example.org", "m.room.member", "@alice:example.org", "$space-join");
    append_event(store, "$space-rules", "!space:example.org", alice, 1'002,
                 "m.room.join_rules", R"({"join_rule":"public"})");
    append_state(store, "!space:example.org", "m.room.join_rules", "", "$space-rules");

    // Child 1 — normal room.
    append_event(store, "$child1-create", "!child1:example.org", alice, 2'000,
                 "m.room.create", "{}");
    append_state(store, "!child1:example.org", "m.room.create", "", "$child1-create");
    append_event(store, "$child1-join", "!child1:example.org", alice, 2'001,
                 "m.room.member", R"({"membership":"join"})");
    append_state(store, "!child1:example.org", "m.room.member", "@alice:example.org", "$child1-join");
    append_event(store, "$child1-rules", "!child1:example.org", alice, 2'002,
                 "m.room.join_rules", R"({"join_rule":"public"})");
    append_state(store, "!child1:example.org", "m.room.join_rules", "", "$child1-rules");
    append_event(store, "$child1-name", "!child1:example.org", alice, 2'003,
                 "m.room.name", R"({"name":"Child One"})");
    append_state(store, "!child1:example.org", "m.room.name", "", "$child1-name");

    // Child 2 — another space.
    append_event(store, "$child2-create", "!child2:example.org", alice, 3'000,
                 "m.room.create", R"({"type":"m.space"})");
    append_state(store, "!child2:example.org", "m.room.create", "", "$child2-create");
    append_event(store, "$child2-join", "!child2:example.org", alice, 3'001,
                 "m.room.member", R"({"membership":"join"})");
    append_state(store, "!child2:example.org", "m.room.member", "@alice:example.org", "$child2-join");
    append_event(store, "$child2-rules", "!child2:example.org", alice, 3'002,
                 "m.room.join_rules", R"({"join_rule":"public"})");
    append_state(store, "!child2:example.org", "m.room.join_rules", "", "$child2-rules");

    // Grandchild — nested under child2.
    append_event(store, "$grandchild-create", "!grandchild:example.org", alice, 4'000,
                 "m.room.create", "{}");
    append_state(store, "!grandchild:example.org", "m.room.create", "", "$grandchild-create");
    append_event(store, "$grandchild-join", "!grandchild:example.org", alice, 4'001,
                 "m.room.member", R"({"membership":"join"})");
    append_state(store, "!grandchild:example.org", "m.room.member", "@alice:example.org", "$grandchild-join");
    append_event(store, "$grandchild-rules", "!grandchild:example.org", alice, 4'002,
                 "m.room.join_rules", R"({"join_rule":"public"})");
    append_state(store, "!grandchild:example.org", "m.room.join_rules", "", "$grandchild-rules");

    // Space child events linking the tree.
    append_event(store, "$root-child1", "!space:example.org", alice, 1'100,
                 "m.space.child", R"({"via":["example.org"],"suggested":true,"order":"a"})");
    append_state(store, "!space:example.org", "m.space.child", "!child1:example.org", "$root-child1");
    append_event(store, "$root-child2", "!space:example.org", alice, 1'101,
                 "m.space.child", R"({"via":["example.org"],"suggested":false})");
    append_state(store, "!space:example.org", "m.space.child", "!child2:example.org", "$root-child2");

    append_event(store, "$child2-grandchild", "!child2:example.org", alice, 3'100,
                 "m.space.child", R"({"via":["example.org"],"suggested":true})");
    append_state(store, "!child2:example.org", "m.space.child", "!grandchild:example.org", "$child2-grandchild");

    return runtime;
}

} // namespace

SCENARIO("handle_client_space_hierarchy returns 404 for a missing room",
         "[homeserver][space-hierarchy][error]")
{
    GIVEN("a runtime with no rooms")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        WHEN("alice requests the hierarchy of a non-existent room")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!missing:example.org"};
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("the request is rejected with M_NOT_FOUND")
            {
                REQUIRE(result.status == 404U);
                auto const body = merovingian::tests::parse_object(result.body);
                REQUIRE(merovingian::tests::string_member(body, "errcode") != nullptr);
                REQUIRE(*merovingian::tests::string_member(body, "errcode") == "M_NOT_FOUND");
            }
        }
    }
}

SCENARIO("handle_client_space_hierarchy returns 403 for an inaccessible room",
         "[homeserver][space-hierarchy][error]")
{
    GIVEN("a private room alice is not in")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        store.rooms = {{"!private:example.org", "@bob:example.org"}};
        append_event(store, "$create", "!private:example.org", "@bob:example.org", 1'000,
                     "m.room.create", "{}");
        append_state(store, "!private:example.org", "m.room.create", "", "$create");
        append_event(store, "$rules", "!private:example.org", "@bob:example.org", 1'001,
                     "m.room.join_rules", R"({"join_rule":"invite"})");
        append_state(store, "!private:example.org", "m.room.join_rules", "", "$rules");
        WHEN("alice requests the hierarchy")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!private:example.org"};
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("the request is rejected with M_FORBIDDEN")
            {
                REQUIRE(result.status == 403U);
                auto const body = merovingian::tests::parse_object(result.body);
                REQUIRE(*merovingian::tests::string_member(body, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}

SCENARIO("handle_client_space_hierarchy returns rooms depth-first",
         "[homeserver][space-hierarchy]")
{
    GIVEN("a public space tree with two levels")
    {
        auto runtime = setup_space_runtime();
        WHEN("alice requests the full hierarchy")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("it succeeds and returns rooms in depth-first order")
            {
                REQUIRE(result.status == 200U);
                auto const body = merovingian::tests::parse_object(result.body);
                auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->size() == 4U);

                auto const room_id = [](canonicaljson::Value const& value) -> std::string {
                    auto const* obj = std::get_if<canonicaljson::Object>(&value.storage());
                    REQUIRE(obj != nullptr);
                    auto const* id = merovingian::tests::string_member(*obj, "room_id");
                    REQUIRE(id != nullptr);
                    return *id;
                };
                REQUIRE(room_id(rooms->at(0)) == "!space:example.org");
                REQUIRE(room_id(rooms->at(1)) == "!child1:example.org");
                REQUIRE(room_id(rooms->at(2)) == "!child2:example.org");
                REQUIRE(room_id(rooms->at(3)) == "!grandchild:example.org");

                auto const* root = std::get_if<canonicaljson::Object>(&rooms->at(0).storage());
                REQUIRE(root != nullptr);
                auto const* children_state = merovingian::tests::object_member_as_array(*root, "children_state");
                REQUIRE(children_state != nullptr);
                REQUIRE(children_state->size() == 2U);
            }
        }
    }
}

SCENARIO("handle_client_space_hierarchy paginates with next_batch",
         "[homeserver][space-hierarchy]")
{
    GIVEN("a public space tree")
    {
        auto runtime = setup_space_runtime();
        WHEN("alice requests one room per page")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org", {}, 1U};
            auto const first =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("the first page contains only the root and a next_batch token")
            {
                REQUIRE(first.status == 200U);
                auto const first_body = merovingian::tests::parse_object(first.body);
                auto const* rooms = merovingian::tests::object_member_as_array(first_body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->size() == 1U);
                auto const* next = merovingian::tests::string_member(first_body, "next_batch");
                REQUIRE(next != nullptr);
                REQUIRE(!next->empty());

                WHEN("the next page is requested with the token")
                {
                    auto next_request = merovingian::homeserver::SpaceHierarchyRequest{
                        "!space:example.org", *next, 1U};
                    auto const second =
                        merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", next_request);
                    THEN("the second page contains the next depth-first room")
                    {
                        REQUIRE(second.status == 200U);
                        auto const second_body = merovingian::tests::parse_object(second.body);
                        auto const* second_rooms = merovingian::tests::object_member_as_array(second_body, "rooms");
                        REQUIRE(second_rooms != nullptr);
                        REQUIRE(second_rooms->size() == 1U);
                        auto const* obj = std::get_if<canonicaljson::Object>(&second_rooms->at(0).storage());
                        REQUIRE(obj != nullptr);
                        REQUIRE(*merovingian::tests::string_member(*obj, "room_id") == "!child1:example.org");
                    }
                }
            }
        }
    }
}

SCENARIO("handle_client_space_hierarchy honours suggested_only",
         "[homeserver][space-hierarchy]")
{
    GIVEN("a public space tree with one suggested child")
    {
        auto runtime = setup_space_runtime();
        WHEN("alice requests only suggested rooms")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            request.suggested_only = true;
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("only the root and directly suggested children appear")
            {
                REQUIRE(result.status == 200U);
                auto const body = merovingian::tests::parse_object(result.body);
                auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->size() == 2U);
                auto const ids = std::vector<std::string>{
                    *merovingian::tests::string_member(
                        *std::get_if<canonicaljson::Object>(&rooms->at(0).storage()), "room_id"),
                    *merovingian::tests::string_member(
                        *std::get_if<canonicaljson::Object>(&rooms->at(1).storage()), "room_id"),
                };
                REQUIRE(ids[0] == "!space:example.org");
                REQUIRE(ids[1] == "!child1:example.org");
            }
        }
    }
}

SCENARIO("handle_client_space_hierarchy honours max_depth",
         "[homeserver][space-hierarchy]")
{
    GIVEN("a public two-level space tree")
    {
        auto runtime = setup_space_runtime();
        WHEN("max_depth is limited to one")
        {
            auto request = merovingian::homeserver::SpaceHierarchyRequest{"!space:example.org"};
            request.max_depth = 1U;
            auto const result =
                merovingian::homeserver::handle_client_space_hierarchy(runtime, "@alice:example.org", request);
            THEN("only the root and its immediate children are returned")
            {
                REQUIRE(result.status == 200U);
                auto const body = merovingian::tests::parse_object(result.body);
                auto const* rooms = merovingian::tests::object_member_as_array(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->size() == 3U);
                auto const* last = std::get_if<canonicaljson::Object>(&rooms->at(2).storage());
                REQUIRE(*merovingian::tests::string_member(*last, "room_id") == "!child2:example.org");
                REQUIRE(merovingian::tests::object_member_as_array(body, "next_batch") == nullptr);
            }
        }
    }
}

SCENARIO("build_federation_space_hierarchy_response returns the room and immediate children",
         "[homeserver][space-hierarchy][federation]")
{
    GIVEN("a public space with children")
    {
        auto runtime = setup_space_runtime();
        WHEN("the federation response is built for the root space")
        {
            auto const body =
                merovingian::homeserver::build_federation_space_hierarchy_response(runtime, "!space:example.org", false);
            THEN("it contains the root room and both children")
            {
                REQUIRE(!body.empty());
                auto const response = merovingian::tests::parse_object(body);
                auto const* room = merovingian::tests::object_member_as_object(response, "room");
                REQUIRE(room != nullptr);
                REQUIRE(*merovingian::tests::string_member(*room, "room_id") == "!space:example.org");

                auto const* children = merovingian::tests::object_member_as_array(response, "children");
                REQUIRE(children != nullptr);
                REQUIRE(children->size() == 2U);
            }
        }
    }
}
