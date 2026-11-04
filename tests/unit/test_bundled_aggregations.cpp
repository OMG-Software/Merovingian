// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/room_history_fixture.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/bundled_aggregations.hpp"
#include "merovingian/sync/history_visibility.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>

namespace
{

using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;
using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;
using merovingian::sync::BundledAggregations;
using namespace merovingian::tests;

constexpr auto room_id = std::string_view{"!room:example.org"};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

auto add(PersistentStore& store, std::string event_id, std::string_view sender, std::string json,
         std::uint64_t stream_ordering, std::string status = "accepted") -> void
{
    auto event = PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::string{room_id};
    event.sender_user_id = std::string{sender};
    event.json = std::move(json);
    event.depth = stream_ordering;
    event.stream_ordering = stream_ordering;
    event.status = std::move(status);
    store.events.push_back(std::move(event));
}

[[nodiscard]] auto message_json(std::string_view sender, std::string_view relates_to = {},
                                std::string_view extra_content = {}) -> std::string
{
    auto json = std::string{R"({"type":"m.room.message","sender":")"} + std::string{sender} +
                R"(","origin_server_ts":1000,"content":{"msgtype":"m.text","body":"x")";
    if (!extra_content.empty())
    {
        json += "," + std::string{extra_content};
    }
    if (!relates_to.empty())
    {
        json += R"(,"m.relates_to":)" + std::string{relates_to};
    }
    return json + "}}";
}

[[nodiscard]] auto relation(std::string_view rel_type, std::string_view target) -> std::string
{
    return R"({"rel_type":")" + std::string{rel_type} + R"(","event_id":")" + std::string{target} + R"("})";
}

[[nodiscard]] auto plain_client_event(PersistentEvent const& event) -> Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(event.json);
    auto object = std::get<Object>(parsed.value.storage());
    object.push_back(merovingian::canonicaljson::make_member("event_id", Value{event.event_id}));
    return Value{std::move(object)};
}

[[nodiscard]] auto aggregate(PersistentStore& store, std::string_view viewer, std::string_view event_id,
                             std::unordered_set<std::string> const& ignored = {}, std::size_t* examined = nullptr,
                             std::size_t* parsed = nullptr) -> Object
{
    merovingian::sync::HistoryVisibility visibility{store, viewer};
    auto aggregations = BundledAggregations{store, visibility, viewer, ignored, [](PersistentEvent const& child) {
                                                return plain_client_event(child);
                                            }};
    auto const found = store.events.find(event_id);
    REQUIRE(found != store.events.end());
    auto served = aggregations.apply(*found, plain_client_event(*found));
    if (examined != nullptr)
    {
        *examined = aggregations.children_examined();
    }
    if (parsed != nullptr)
    {
        *parsed = aggregations.children_parsed();
    }
    return std::get<Object>(served.storage());
}

[[nodiscard]] auto thread_of(Object const& event) -> Object const*
{
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    auto const* relations = unsigned_data == nullptr ? nullptr : object_member_as_object(*unsigned_data, "m.relations");
    return relations == nullptr ? nullptr : object_member_as_object(*relations, "m.thread");
}

} // namespace

SCENARIO("Serving an event reads only its own children, however large the table is",
         "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a thread root with one reply, among many unrelated events")
    {
        auto small = PersistentStore{};
        auto large = PersistentStore{};
        for (auto* store : {&small, &large})
        {
            add(*store, "$root", alice, message_json(alice), 1U);
            add(*store, "$reply", bob, message_json(bob, relation("m.thread", "$root")), 2U);
        }
        for (auto index = std::uint64_t{0U}; index < 3000U; ++index)
        {
            add(large, "$noise" + std::to_string(index), bob, message_json(bob), 10U + index);
        }
        record_joined_state_for_room(small, room_id, alice);
        record_joined_state_for_room(large, room_id, alice);

        WHEN("the root is served from each table")
        {
            auto small_examined = std::size_t{0U};
            auto large_examined = std::size_t{0U};
            auto small_parsed = std::size_t{0U};
            auto large_parsed = std::size_t{0U};
            auto const from_small = aggregate(small, alice, "$root", {}, &small_examined, &small_parsed);
            auto const from_large = aggregate(large, alice, "$root", {}, &large_examined, &large_parsed);

            THEN("the work is the one child, whatever the table holds, and no child JSON was parsed")
            {
                REQUIRE(small_examined == 1U);
                REQUIRE(large_examined == 1U);
                REQUIRE(small_parsed == 0U);
                REQUIRE(large_parsed == 0U);
                REQUIRE(thread_of(from_small) != nullptr);
                REQUIRE(thread_of(from_large) != nullptr);
            }
        }

        WHEN("an event with no children is served")
        {
            auto examined = std::size_t{0U};
            auto const served = aggregate(large, alice, "$noise7", {}, &examined);

            THEN("no child is looked at and nothing is added")
            {
                REQUIRE(examined == 0U);
                REQUIRE(thread_of(served) == nullptr);
            }
        }
    }
}

SCENARIO("An aggregation is capped however many children an event has", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a root with more replies than one event may examine")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        auto const replies = merovingian::sync::max_aggregated_children_examined + 50U;
        for (auto index = std::size_t{0U}; index < replies; ++index)
        {
            add(store, "$reply" + std::to_string(index), bob, message_json(bob, relation("m.thread", "$root")),
                2U + index);
        }
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the root is served")
        {
            auto examined = std::size_t{0U};
            auto const served = aggregate(store, alice, "$root", {}, &examined);

            THEN("only the cap is examined, newest first, so the latest reply is the latest event")
            {
                REQUIRE(examined == merovingian::sync::max_aggregated_children_examined);
                auto const* thread = thread_of(served);
                REQUIRE(thread != nullptr);
                REQUIRE(*int_member(*thread, "count") ==
                        static_cast<std::int64_t>(merovingian::sync::max_aggregated_children_examined));
                auto const* latest = object_member_as_object(*thread, "latest_event");
                REQUIRE(*string_member(*latest, "event_id") == "$reply" + std::to_string(replies - 1U));
            }
        }
    }
}

SCENARIO("A refused or ignored child is not counted", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a root with an accepted reply, a rejected one, a soft-failed one and one from an ignored user")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        add(store, "$ok", bob, message_json(bob, relation("m.thread", "$root")), 2U);
        add(store, "$rejected", bob, message_json(bob, relation("m.thread", "$root")), 3U, "rejected");
        add(store, "$soft", bob, message_json(bob, relation("m.thread", "$root")), 4U, "soft_failed");
        add(store, "$ignored", "@mallory:example.org",
            message_json("@mallory:example.org", relation("m.thread", "$root")), 5U);
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the root is served to a viewer who ignores mallory")
        {
            auto const served = aggregate(store, alice, "$root", {"@mallory:example.org"});

            THEN("only the accepted reply counts and it is the latest event")
            {
                auto const* thread = thread_of(served);
                REQUIRE(thread != nullptr);
                REQUIRE(*int_member(*thread, "count") == 1);
                REQUIRE(*string_member(*object_member_as_object(*thread, "latest_event"), "event_id") == "$ok");
            }
        }
    }
}

SCENARIO("The latest event of a thread carries its own aggregation", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a root, a reply, and a valid edit of the reply")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        add(store, "$reply", bob, message_json(bob, relation("m.thread", "$root")), 2U);
        add(store, "$edit", bob,
            message_json(bob, relation("m.replace", "$reply"), R"("m.new_content":{"msgtype":"m.text","body":"y"})"),
            3U);
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the root is served")
        {
            auto const served = aggregate(store, alice, "$root");

            THEN("latest_event has m.replace, and that bundle does not nest further")
            {
                auto const* thread = thread_of(served);
                REQUIRE(thread != nullptr);
                auto const* latest = object_member_as_object(*thread, "latest_event");
                REQUIRE(latest != nullptr);
                auto const* unsigned_data = object_member_as_object(*latest, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                auto const* relations = object_member_as_object(*unsigned_data, "m.relations");
                REQUIRE(relations != nullptr);
                auto const* replace = object_member_as_object(*relations, "m.replace");
                REQUIRE(replace != nullptr);
                REQUIRE(*string_member(*replace, "event_id") == "$edit");
                REQUIRE(object_member_as_object(*replace, "unsigned") == nullptr);
            }
        }
    }
}

SCENARIO("One relation kind cannot use up the examined window of another", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a root edited early, then more thread replies and references than one window holds")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        add(store, "$edit", alice,
            message_json(alice, relation("m.replace", "$root"), R"("m.new_content":{"msgtype":"m.text","body":"y"})"),
            2U);
        auto const flood = merovingian::sync::max_aggregated_children_examined + 952U;
        for (auto index = std::size_t{0U}; index < flood; ++index)
        {
            add(store, "$reply" + std::to_string(index), bob, message_json(bob, relation("m.thread", "$root")),
                10U + index);
            add(store, "$ref" + std::to_string(index), bob, message_json(bob, relation("m.reference", "$root")),
                100000U + index);
        }
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the root is served")
        {
            auto const served = aggregate(store, alice, "$root");

            THEN("the early edit is still bundled, and so are the thread and the references")
            {
                auto const* unsigned_data = object_member_as_object(served, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                auto const* relations = object_member_as_object(*unsigned_data, "m.relations");
                REQUIRE(relations != nullptr);
                auto const* replace = object_member_as_object(*relations, "m.replace");
                REQUIRE(replace != nullptr);
                REQUIRE(*string_member(*replace, "event_id") == "$edit");
                REQUIRE(object_member_as_object(*relations, "m.thread") != nullptr);
                auto const* reference = object_member_as_object(*relations, "m.reference");
                REQUIRE(reference != nullptr);
                REQUIRE(object_member_as_array(*reference, "chunk")->size() ==
                        merovingian::sync::max_reference_chunk_entries);
            }
        }
    }
}

SCENARIO("A reaction is not a child the aggregation looks at", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a message with a thread reply and many reactions")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        add(store, "$reply", bob, message_json(bob, relation("m.thread", "$root")), 2U);
        for (auto index = std::size_t{0U}; index < 50U; ++index)
        {
            add(store, "$react" + std::to_string(index), bob, message_json(bob, relation("m.annotation", "$root")),
                10U + index);
        }
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the root is served")
        {
            auto examined = std::size_t{0U};
            auto const served = aggregate(store, alice, "$root", {}, &examined);

            THEN("the reactions cost no window, and are not indexed at all")
            {
                REQUIRE(examined == 1U);
                REQUIRE(store.events.relation_child_count("$root") == 1U);
                REQUIRE(thread_of(served) != nullptr);
            }
        }
    }
}

SCENARIO("An edit by an ignored sender is not used", "[sync][aggregations][bundled-aggregations]")
{
    GIVEN("a message and a valid edit of it by its own sender")
    {
        auto store = PersistentStore{};
        add(store, "$root", alice, message_json(alice), 1U);
        add(store, "$edit", alice,
            message_json(alice, relation("m.replace", "$root"), R"("m.new_content":{"msgtype":"m.text","body":"y"})"),
            2U);
        record_joined_state_for_room(store, room_id, alice);

        WHEN("the sender is in the viewer's ignored set")
        {
            auto const served = aggregate(store, alice, "$root", {std::string{alice}});

            THEN("no m.replace is bundled")
            {
                REQUIRE(object_member_as_object(served, "unsigned") == nullptr);
            }
        }
    }
}
