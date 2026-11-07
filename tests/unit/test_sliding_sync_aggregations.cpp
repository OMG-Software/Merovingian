// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/room_history_fixture.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/sync/SlidingSyncRoomResponse.hpp"
#include "merovingian/sync/SlidingSyncRoomSubscription.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;

constexpr auto room_id = std::string_view{"!room:example.org"};

auto add(PersistentStore& store, std::string event_id, std::string_view sender, std::string json,
         std::uint64_t stream_ordering) -> void
{
    auto event = PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::string{room_id};
    event.sender_user_id = std::string{sender};
    event.json = std::move(json);
    event.depth = stream_ordering;
    event.stream_ordering = stream_ordering;
    store.events.push_back(std::move(event));
}

[[nodiscard]] auto message(std::string_view sender, std::string_view content_extra = {},
                           std::string_view top_extra = {}) -> std::string
{
    auto json = std::string{R"({"type":"m.room.message","sender":")"} + std::string{sender} +
                R"(","origin_server_ts":1000,"content":{"msgtype":"m.text","body":"x")";
    if (!content_extra.empty())
    {
        json += "," + std::string{content_extra};
    }
    json += "}";
    if (!top_extra.empty())
    {
        json += "," + std::string{top_extra};
    }
    return json + "}";
}

constexpr auto thread_of_root = std::string_view{R"("m.relates_to":{"rel_type":"m.thread","event_id":"$root"})"};
constexpr auto edit_of_root = std::string_view{
    R"("m.new_content":{"msgtype":"m.text","body":"y"},"m.relates_to":{"rel_type":"m.replace","event_id":"$root"})"};
constexpr auto forged_unsigned = std::string_view{R"("unsigned":{"m.relations":{"m.thread":{"count":99,"FORGED":1}}})"};

// A root, a reply, an edit of the root, and an older message, so a small timeline limit cuts the room.
auto fill(PersistentStore& store, bool forge) -> void
{
    auto const unsigned_text = forge ? forged_unsigned : std::string_view{};
    add(store, "$filler", "@bob:example.org", message("@bob:example.org"), 5U);
    add(store, "$root", "@alice:example.org", message("@alice:example.org", {}, unsigned_text), 10U);
    add(store, "$reply", "@bob:example.org", message("@bob:example.org", thread_of_root, unsigned_text), 11U);
    add(store, "$edit", "@alice:example.org", message("@alice:example.org", edit_of_root, unsigned_text), 12U);
    merovingian::tests::record_joined_state_for_room(store, room_id, "@alice:example.org");
}

[[nodiscard]] auto build(PersistentStore const& store, std::uint32_t timeline_limit,
                         std::unordered_set<std::string> const& ignored = {})
    -> merovingian::sync::SlidingSyncRoomResponse
{
    auto runtime = merovingian::homeserver::HomeserverRuntime{};
    auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
    sub.timeline_limit = timeline_limit;
    return merovingian::sync::build_room_response(runtime, room_id, "@alice:example.org", sub, 0U, true, store, {},
                                                  ignored);
}

[[nodiscard]] auto root_json(merovingian::sync::SlidingSyncRoomResponse const& response) -> std::string
{
    for (auto const& json : response.timeline_json)
    {
        if (json.find(R"("event_id":"$root")") != std::string::npos)
        {
            return json;
        }
    }
    return {};
}

} // namespace

SCENARIO("A limited sliding sync room carries bundled aggregations on the events it keeps",
         "[sync][sliding-sync][aggregations][bundled-aggregations]")
{
    GIVEN("a room whose timeline limit cuts off its oldest event")
    {
        auto store = PersistentStore{};
        fill(store, false);

        WHEN("the room response is built with a limit of three")
        {
            auto const response = build(store, 3U);

            THEN("the room is limited and the root carries its thread and its edit")
            {
                REQUIRE(response.limited);
                auto const json = root_json(response);
                REQUIRE_FALSE(json.empty());
                REQUIRE(json.find(R"("m.thread")") != std::string::npos);
                REQUIRE(json.find(R"("count":1)") != std::string::npos);
                REQUIRE(json.find(R"("m.replace")") != std::string::npos);
            }
        }

        WHEN("the room response is built with a limit that holds the whole room")
        {
            auto const response = build(store, 20U);

            THEN("the room is not limited and no event carries m.relations")
            {
                REQUIRE_FALSE(response.limited);
                auto const json = root_json(response);
                REQUIRE_FALSE(json.empty());
                REQUIRE(json.find("m.relations") == std::string::npos);
            }
        }
    }
}

SCENARIO("A sender-controlled unsigned never reaches a sliding sync client, nested or not",
         "[sync][sliding-sync][aggregations][bundled-aggregations]")
{
    GIVEN("a limited room whose root, reply and edit all store a forged unsigned.m.relations")
    {
        auto store = PersistentStore{};
        fill(store, true);

        WHEN("the room response is built")
        {
            auto const response = build(store, 3U);

            THEN("nothing forged is served, and the real aggregation is")
            {
                REQUIRE(response.limited);
                for (auto const& json : response.timeline_json)
                {
                    REQUIRE(json.find("FORGED") == std::string::npos);
                }
                auto const json = root_json(response);
                REQUIRE(json.find(R"("count":1)") != std::string::npos);
                REQUIRE(json.find(R"("count":99)") == std::string::npos);
            }
        }
    }
}

SCENARIO("A reply from an ignored sender is not counted in a sliding sync aggregation",
         "[sync][sliding-sync][aggregations][bundled-aggregations]")
{
    GIVEN("a limited room whose only reply is from bob, and a viewer who ignores bob")
    {
        auto store = PersistentStore{};
        fill(store, false);

        WHEN("the room response is built with bob ignored")
        {
            auto const response = build(store, 3U, {"@bob:example.org"});

            THEN("the root has no thread")
            {
                auto const json = root_json(response);
                REQUIRE_FALSE(json.empty());
                REQUIRE(json.find(R"("m.thread")") == std::string::npos);
            }
        }
    }
}
