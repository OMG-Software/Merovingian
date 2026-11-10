// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for sync::ViewerEventUnsigned.
//
// Spec (client-server-api.md, ClientEvent `unsigned`): `transaction_id` is given only to the client that
// sent the event; `membership` is "The room membership of the user making the request, at the time of the
// event"; `prev_content` is the content of the state event replaced, when the viewer may see it.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/database/PersistentClientTxnRecord.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/HistoryVisibility.hpp"
#include "merovingian/sync/ViewerEventUnsigned.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;

constexpr auto room = std::string_view{"!room:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

auto add_event(PersistentStore& store, std::string_view event_id, std::string json, std::uint64_t ordering) -> void
{
    auto event = PersistentEvent{};
    event.event_id = std::string{event_id};
    event.room_id = std::string{room};
    event.sender_user_id = "@alice:example.org";
    event.json = std::move(json);
    event.stream_ordering = ordering;
    event.depth = ordering;
    store.events.push_back(std::move(event));
}

// A room where bob is joined and every event below is in the state group "g1".
[[nodiscard]] auto joined_room() -> PersistentStore
{
    auto store = PersistentStore{};
    add_event(store, "$member",
              R"({"type":"m.room.member","state_key":"@bob:example.org","content":{"membership":"join"}})", 1U);
    add_event(store, "$n1", R"({"type":"m.room.name","state_key":"","content":{"name":"old"}})", 2U);
    add_event(store, "$n2", R"({"type":"m.room.name","state_key":"","content":{"name":"new"}})", 3U);
    add_event(store, "$msg", R"({"type":"m.room.message","content":{"body":"x"}})", 4U);
    std::ignore = store.state_groups.insert({"g1", std::string{room}, std::nullopt, 0U});
    store.state_group_state.insert({"g1", "m.room.member", std::string{bob}, "$member"});
    for (auto const* id : {"$member", "$n1", "$n2", "$msg"})
    {
        store.event_state_groups.assign(id, "g1");
    }
    store.state_transitions.push_back({std::string{room}, "m.room.name", "", "$n2", "$n1"});
    merovingian::database::rebuild_state_transition_index(store);
    return store;
}

[[nodiscard]] auto value_of(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto text_of(merovingian::canonicaljson::Value const& value) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(value).output;
}

auto record_send(PersistentStore& store, std::string_view user, std::string_view device) -> void
{
    auto record = merovingian::database::PersistentClientTxnRecord{};
    record.user_id = std::string{user};
    record.room_id = std::string{room};
    record.event_type = "m.room.message";
    record.txn_id = "txn-7";
    record.event_id = "$msg";
    record.device_id = std::string{device};
    store.client_txn_ids.push_back(std::move(record));
}

} // namespace

SCENARIO("A viewer's unsigned fields are added to a client event", "[sync][unsigned][unit]")
{
    GIVEN("a room where bob is joined and a message that bob's device D sent with a transaction ID")
    {
        auto store = joined_room();
        record_send(store, bob, "D");
        auto const& message = *store.events.find("$msg");

        WHEN("the sending device is served the event")
        {
            auto visibility = merovingian::sync::HistoryVisibility{store, bob};
            auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, bob, "D"};
            auto const served = viewer.apply(message, value_of(R"({"type":"m.room.message","content":{}})"));

            THEN("it is given the transaction_id and its membership at the event")
            {
                REQUIRE(
                    text_of(served) ==
                    R"({"content":{},"type":"m.room.message","unsigned":{"membership":"join","transaction_id":"txn-7"}})");
            }
        }

        WHEN("another device of the same user is served the event")
        {
            auto visibility = merovingian::sync::HistoryVisibility{store, bob};
            auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, bob, "OTHER"};
            auto const served = viewer.apply(message, value_of(R"({"type":"m.room.message"})"));

            THEN("it gets the membership but no transaction_id")
            {
                REQUIRE(text_of(served) == R"({"type":"m.room.message","unsigned":{"membership":"join"}})");
            }
        }

        WHEN("a viewer with no device is served the event")
        {
            auto visibility = merovingian::sync::HistoryVisibility{store, bob};
            auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, bob, ""};
            auto const served = viewer.apply(message, value_of(R"({"type":"m.room.message"})"));

            THEN("no transaction_id is given")
            {
                REQUIRE(text_of(served).find("transaction_id") == std::string::npos);
            }
        }

        WHEN("another user whose device has the same ID is served the event")
        {
            auto visibility = merovingian::sync::HistoryVisibility{store, "@mallory:example.org"};
            auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, "@mallory:example.org", "D"};
            auto const served = viewer.apply(message, value_of(R"({"type":"m.room.message"})"));

            THEN("no transaction_id is given")
            {
                REQUIRE(text_of(served).find("transaction_id") == std::string::npos);
            }
        }
    }
}

SCENARIO("Existing unsigned members survive unless the viewer's value replaces them", "[sync][unsigned][unit]")
{
    GIVEN("a client event that already carries an unsigned object")
    {
        auto store = joined_room();
        auto const& message = *store.events.find("$msg");
        auto visibility = merovingian::sync::HistoryVisibility{store, bob};
        auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, bob, "D"};

        WHEN("the viewer's fields are applied")
        {
            auto const served = viewer.apply(
                message, value_of(R"({"type":"m.room.message","unsigned":{"age":5,"membership":"stale"}})"));

            THEN("age is kept and the stale membership is replaced")
            {
                REQUIRE(text_of(served) == R"({"type":"m.room.message","unsigned":{"age":5,"membership":"join"}})");
            }
        }

        WHEN("a value that is not an object is applied")
        {
            auto const served = viewer.apply(message, value_of("[1]"));

            THEN("it is returned unchanged")
            {
                REQUIRE(text_of(served) == "[1]");
            }
        }
    }
}

SCENARIO("A state event is given the content it replaced when the viewer may see it", "[sync][unsigned][unit]")
{
    GIVEN("a room name changed from old to new")
    {
        auto store = joined_room();
        auto visibility = merovingian::sync::HistoryVisibility{store, bob};
        auto viewer = merovingian::sync::ViewerEventUnsigned{store, visibility, bob, "D"};

        WHEN("the replacing state event is served")
        {
            auto const served =
                viewer.apply(*store.events.find("$n2"),
                             value_of(R"({"type":"m.room.name","state_key":"","content":{"name":"new"}})"));

            THEN("unsigned.prev_content is the old content")
            {
                REQUIRE(text_of(served).find(R"("prev_content":{"name":"old"})") != std::string::npos);
            }
        }

        WHEN("a state event with nothing before it is served")
        {
            auto const served =
                viewer.apply(*store.events.find("$n1"),
                             value_of(R"({"type":"m.room.name","state_key":"","content":{"name":"old"}})"));

            THEN("there is no prev_content")
            {
                REQUIRE(text_of(served).find("prev_content") == std::string::npos);
            }
        }

        WHEN("a non-state event is served")
        {
            auto const served =
                viewer.apply(*store.events.find("$msg"), value_of(R"({"type":"m.room.message","content":{}})"));

            THEN("there is no prev_content")
            {
                REQUIRE(text_of(served).find("prev_content") == std::string::npos);
            }
        }
    }
}
