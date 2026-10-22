// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/room_access.hpp"
#include "merovingian/sync/sliding_sync_extensions.hpp"
#include "merovingian/sync/sliding_sync_room_list.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::canonicaljson::Array;
using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;

[[nodiscard]] auto json_member(Object const& object, std::string_view key) -> Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto object_member(Object const& object, std::string_view key) -> Object const*
{
    auto const* value = json_member(object, key);
    return value != nullptr ? std::get_if<Object>(&value->storage()) : nullptr;
}

[[nodiscard]] auto string_member(Object const& object, std::string_view key) -> std::string const*
{
    auto const* value = json_member(object, key);
    return value != nullptr ? std::get_if<std::string>(&value->storage()) : nullptr;
}

[[nodiscard]] auto array_member(Object const& object, std::string_view key) -> Array const*
{
    auto const* value = json_member(object, key);
    return value != nullptr ? std::get_if<Array>(&value->storage()) : nullptr;
}

[[nodiscard]] auto parse_object(std::string_view json) -> Object
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* object = std::get_if<Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

auto append_event(merovingian::database::PersistentStore& store, std::string_view event_id, std::string_view room_id,
                  std::string_view json, std::uint64_t stream_ordering) -> void
{
    store.events.push_back({
        std::string{event_id},
        std::string{room_id},
        "@alice:example.org",
        std::string{json},
        1U,
        stream_ordering,
        {},
        {},
        {},
    });
}

// Messages that should count as unread for @alice must come from someone
// else — a user's own messages are never notifications (#417).
auto append_event_from(merovingian::database::PersistentStore& store, std::string_view sender,
                       std::string_view event_id, std::string_view room_id, std::string_view json,
                       std::uint64_t stream_ordering) -> void
{
    store.events.push_back({
        std::string{event_id},
        std::string{room_id},
        std::string{sender},
        std::string{json},
        1U,
        stream_ordering,
        {},
        {},
        {},
    });
}

auto append_state(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view event_type,
                  std::string_view state_key, std::string_view event_id) -> void
{
    store.state.push_back({
        std::string{room_id},
        std::string{event_type},
        std::string{state_key},
        std::string{event_id},
    });
}

// One event of the sp01 ordering fixture. `name` is set only for an m.room.name event, which is
// also recorded as the room's current name state.
struct SortFixtureEvent final
{
    char room;
    std::string type;
    std::uint64_t stream_ordering;
    std::string name{};
};

[[nodiscard]] auto sort_fixture_room_id(char room) -> std::string
{
    return std::string{"!"} + room + ":example.org";
}

// Fixed history for eight rooms ("a".."h"). Stream orderings are unique across the fixture.
//   room  messages  other events  name
//   a     10        topic 95      Delta (5)
//   b     50        -             Alpha (6)
//   c     30        topic 60      -
//   d     70        -             Alpha (7)
//   e     20        topic 80      -
//   f     61        -             Bravo (9)
//   g     -         topic 85      -
//   h     -         topic 15      Echo (8)
[[nodiscard]] auto sort_fixture_events() -> std::vector<SortFixtureEvent>
{
    return {
        {'a', "m.room.message", 10U},
        {'a', "m.room.topic", 95U},
        {'a', "m.room.name", 5U, "Delta"},
        {'b', "m.room.message", 50U},
        {'b', "m.room.name", 6U, "Alpha"},
        {'c', "m.room.message", 30U},
        {'c', "m.room.topic", 60U},
        {'d', "m.room.message", 70U},
        {'d', "m.room.name", 7U, "Alpha"},
        {'e', "m.room.message", 20U},
        {'e', "m.room.topic", 80U},
        {'f', "m.room.message", 61U},
        {'f', "m.room.name", 9U, "Bravo"},
        {'g', "m.room.topic", 85U},
        {'h', "m.room.topic", 15U},
        {'h', "m.room.name", 8U, "Echo"},
    };
}

// Alice is joined to every fixture room, listed in descending ID order so that neither the room
// order nor the final room-ID tie-break can be satisfied by accident. Events enter store.events
// in exactly the order given.
[[nodiscard]] auto make_sort_fixture_store(std::vector<SortFixtureEvent> const& events)
    -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    auto membership_ordering = std::uint64_t{1U};
    for (auto room = 'h'; room >= 'a'; --room)
    {
        store.rooms.push_back({sort_fixture_room_id(room), "@alice:example.org"});
        store.memberships.push_back({sort_fixture_room_id(room), "@alice:example.org", "join", membership_ordering++});
    }
    for (auto const& event : events)
    {
        auto const room_id = sort_fixture_room_id(event.room);
        auto const event_id = "$" + std::string{event.room} + std::to_string(event.stream_ordering);
        auto const json = event.name.empty()
                              ? R"({"type":")" + event.type + R"(","content":{}})"
                              : R"({"type":")" + event.type + R"(","content":{"name":")" + event.name + R"("}})";
        append_event(store, event_id, room_id, json, event.stream_ordering);
        if (!event.name.empty())
        {
            append_state(store, room_id, event.type, "", event_id);
        }
    }
    return store;
}

[[nodiscard]] auto sort_fixture_rooms(std::string_view letters) -> std::vector<std::string>
{
    auto out = std::vector<std::string>{};
    for (auto const letter : letters)
    {
        out.push_back(sort_fixture_room_id(letter));
    }
    return out;
}

[[nodiscard]] auto sorted_rooms(merovingian::database::PersistentStore const& store, std::vector<std::string> sort,
                                std::vector<std::string> bump_event_types) -> std::vector<std::string>
{
    auto const runtime = merovingian::homeserver::HomeserverRuntime{};
    auto list = merovingian::sync::SlidingSyncList{};
    list.ranges = {
        {0U, 20U}
    };
    list.sort = std::move(sort);
    list.bump_event_types = std::move(bump_event_types);
    return merovingian::sync::compute_room_list(runtime, "@alice:example.org", list, {}, store).windowed_room_ids;
}

} // namespace

SCENARIO("Sliding sync room lists apply DM and room metadata filters before sorting", "[sync][sliding-sync][room-list]")
{
    GIVEN("three joined rooms with different encryption, direct-message, favourite, and type metadata")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.database.rooms = {
            {"!alpha:example.org", "@alice:example.org", {}, {}, false},
            {"!beta:example.org",  "@alice:example.org", {}, {}, false},
            {"!gamma:example.org", "@alice:example.org", {}, {}, false},
        };

        auto store = merovingian::database::PersistentStore{};
        store.rooms = {
            {"!alpha:example.org", "@alice:example.org"},
            {"!beta:example.org",  "@alice:example.org"},
            {"!gamma:example.org", "@alice:example.org"},
        };
        store.memberships = {
            {"!alpha:example.org", "@alice:example.org", "join", 1U},
            {"!beta:example.org",  "@alice:example.org", "join", 2U},
            {"!gamma:example.org", "@alice:example.org", "join", 3U},
        };

        append_event(store, "$alpha-create", "!alpha:example.org",
                     R"({"type":"m.room.create","content":{"type":"m.space"}})", 10U);
        append_state(store, "!alpha:example.org", "m.room.create", "", "$alpha-create");
        append_event(store, "$alpha-name", "!alpha:example.org", R"({"type":"m.room.name","content":{"name":"Alpha"}})",
                     11U);
        append_state(store, "!alpha:example.org", "m.room.name", "", "$alpha-name");
        append_event(store, "$alpha-encryption", "!alpha:example.org",
                     R"({"type":"m.room.encryption","content":{"algorithm":"m.megolm.v1.aes-sha2"}})", 12U);
        append_state(store, "!alpha:example.org", "m.room.encryption", "", "$alpha-encryption");

        append_event(store, "$beta-create", "!beta:example.org",
                     R"({"type":"m.room.create","content":{"type":"m.server_notice"}})", 20U);
        append_state(store, "!beta:example.org", "m.room.create", "", "$beta-create");
        append_event(store, "$beta-name", "!beta:example.org", R"({"type":"m.room.name","content":{"name":"Beta"}})",
                     21U);
        append_state(store, "!beta:example.org", "m.room.name", "", "$beta-name");

        append_event(store, "$gamma-create", "!gamma:example.org",
                     R"({"type":"m.room.create","content":{"type":"m.space"}})", 30U);
        append_state(store, "!gamma:example.org", "m.room.create", "", "$gamma-create");
        append_event(store, "$gamma-name", "!gamma:example.org", R"({"type":"m.room.name","content":{"name":"Gamma"}})",
                     31U);
        append_state(store, "!gamma:example.org", "m.room.name", "", "$gamma-name");
        append_event(store, "$gamma-encryption", "!gamma:example.org",
                     R"({"type":"m.room.encryption","content":{"algorithm":"m.megolm.v1.aes-sha2"}})", 32U);
        append_state(store, "!gamma:example.org", "m.room.encryption", "", "$gamma-encryption");

        store.account_data = {
            {"@alice:example.org", "",                   "m.direct",
             R"({"@bob:example.org":["!alpha:example.org"],"@carol:example.org":["!elsewhere:example.org"]})", 1U},
            {"@alice:example.org", "!alpha:example.org", "m.tag",    R"({"tags":{"m.favourite":{}}})",         2U},
            {"@alice:example.org", "!gamma:example.org", "m.tag",    R"({"tags":{"m.lowpriority":{}}})",       3U},
        };

        auto list = merovingian::sync::SlidingSyncList{};
        list.ranges = {
            {0U, 9U}
        };
        list.sort = {"by_name"};
        list.filters = merovingian::sync::SlidingSyncFilters{
            true, false, true, true, {"m.space"}, {"m.server_notice"},
        };

        WHEN("the room list is computed for Alice")
        {
            auto const result = merovingian::sync::compute_room_list(runtime, "@alice:example.org", list, {}, store);

            THEN("only the favourited encrypted DM with the allowed room type remains")
            {
                REQUIRE(result.count == 1U);
                REQUIRE(result.windowed_room_ids == std::vector<std::string>{"!alpha:example.org"});
                REQUIRE(result.ops.size() == 1U);
                REQUIRE(result.ops.front().op == "SYNC");
                REQUIRE(result.ops.front().range.has_value());
                REQUIRE(result.ops.front().range->start == 0U);
                REQUIRE(result.ops.front().range->end == 9U);
                REQUIRE(result.ops.front().room_ids == std::vector<std::string>{"!alpha:example.org"});
            }
        }
    }
}

SCENARIO("Sliding sync room lists emit incremental sync ops when notification and recency ordering changes",
         "[sync][sliding-sync][room-list]")
{
    GIVEN("three joined rooms with different unread counts and bump-event recency")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.database.rooms = {
            {"!alpha:example.org", "@alice:example.org", {}, {}, false},
            {"!beta:example.org",  "@alice:example.org", {}, {}, false},
            {"!gamma:example.org", "@alice:example.org", {}, {}, false},
        };

        auto store = merovingian::database::PersistentStore{};
        store.rooms = {
            {"!alpha:example.org", "@alice:example.org"},
            {"!beta:example.org",  "@alice:example.org"},
            {"!gamma:example.org", "@alice:example.org"},
        };
        store.memberships = {
            {"!alpha:example.org", "@alice:example.org", "join", 1U},
            {"!beta:example.org",  "@alice:example.org", "join", 2U},
            {"!gamma:example.org", "@alice:example.org", "join", 3U},
        };

        append_event(store, "$alpha-name", "!alpha:example.org", R"({"type":"m.room.name","content":{"name":"Alpha"}})",
                     1U);
        append_state(store, "!alpha:example.org", "m.room.name", "", "$alpha-name");
        append_event(store, "$beta-name", "!beta:example.org", R"({"type":"m.room.name","content":{"name":"Beta"}})",
                     2U);
        append_state(store, "!beta:example.org", "m.room.name", "", "$beta-name");
        append_event(store, "$gamma-name", "!gamma:example.org", R"({"type":"m.room.name","content":{"name":"Gamma"}})",
                     3U);
        append_state(store, "!gamma:example.org", "m.room.name", "", "$gamma-name");

        append_event_from(store, "@bob:example.org", "$alpha-message", "!alpha:example.org",
                          R"({"type":"m.room.message","content":{"body":"alpha"}})", 4U);
        append_event_from(store, "@bob:example.org", "$beta-message-1", "!beta:example.org",
                          R"({"type":"m.room.message","content":{"body":"beta-1"}})", 5U);
        append_event_from(store, "@bob:example.org", "$beta-message-2", "!beta:example.org",
                          R"({"type":"m.room.message","content":{"body":"beta-2"}})", 6U);
        append_event_from(store, "@bob:example.org", "$gamma-encrypted", "!gamma:example.org",
                          R"({"type":"m.room.encrypted","content":{"ciphertext":"..."}})", 7U);

        auto list = merovingian::sync::SlidingSyncList{};
        list.ranges = {
            {0U, 1U}
        };
        list.sort = {"by_notification_count", "by_recency", "by_name"};
        list.bump_event_types = {"m.room.encrypted"};

        WHEN("the previous window no longer matches the sorted order")
        {
            auto const result = merovingian::sync::compute_room_list(
                runtime, "@alice:example.org", list, {"!alpha:example.org", "!beta:example.org"}, store);

            THEN("the changed window is re-synced in the new notification and recency order")
            {
                REQUIRE(result.count == 3U);
                REQUIRE(result.windowed_room_ids == std::vector<std::string>{
                                                        "!beta:example.org",
                                                        "!gamma:example.org",
                                                    });
                REQUIRE(result.ops.size() == 1U);
                REQUIRE(result.ops.front().op == "SYNC");
                REQUIRE(result.ops.front().range.has_value());
                REQUIRE(result.ops.front().range->start == 0U);
                REQUIRE(result.ops.front().range->end == 1U);
                REQUIRE(result.ops.front().room_ids == std::vector<std::string>{
                                                           "!beta:example.org",
                                                           "!gamma:example.org",
                                                       });
            }
        }
    }
}

SCENARIO("Sliding sync room lists sort by threaded unread notifications and break ties by room ID",
         "[sync][sliding-sync][room-list][receipts]")
{
    GIVEN("joined rooms with different unread counts, including a thread receipt that leaves the main event unread")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};
        auto const room_ids = std::vector<std::string>{
            "!alpha:example.org",
            "!beta:example.org",
            "!delta:example.org",
            "!gamma:example.org",
        };
        for (std::size_t i = 0U; i < room_ids.size(); ++i)
        {
            store.rooms.push_back({room_ids[i], "@alice:example.org"});
            store.memberships.push_back({room_ids[i], "@alice:example.org", "join", i + 1U});
        }

        append_event_from(store, "@bob:example.org", "$alpha-root", room_ids[0],
                          R"({"type":"m.room.message","content":{"body":"root"}})", 10U);
        append_event_from(
            store, "@bob:example.org", "$alpha-reply", room_ids[0],
            R"({"type":"m.room.message","content":{"body":"reply","m.relates_to":{"rel_type":"m.thread","event_id":"$alpha-root"}}})",
            11U);
        runtime.database.persistent_store.receipts.push_back(
            {room_ids[0], "m.read", "@alice:example.org", "$alpha-reply", 0U, 1U, "$alpha-root"});

        append_event_from(store, "@bob:example.org", "$beta-one", room_ids[1],
                          R"({"type":"m.room.message","content":{"body":"one"}})", 20U);
        append_event_from(store, "@bob:example.org", "$beta-two", room_ids[1],
                          R"({"type":"m.room.message","content":{"body":"two"}})", 21U);
        append_event_from(store, "@bob:example.org", "$delta-one", room_ids[2],
                          R"({"type":"m.room.message","content":{"body":"one"}})", 30U);

        auto list = merovingian::sync::SlidingSyncList{};
        list.ranges = {
            {0U, 3U}
        };
        list.sort = {"by_notification_count"};

        WHEN("the room list is sorted by unread notification count")
        {
            auto const result = merovingian::sync::compute_room_list(runtime, "@alice:example.org", list, {}, store);

            THEN("thread unread counts are respected and equal counts use lexical room ID order")
            {
                REQUIRE(result.windowed_room_ids == std::vector<std::string>{
                                                        "!beta:example.org",
                                                        "!alpha:example.org",
                                                        "!delta:example.org",
                                                        "!gamma:example.org",
                                                    });
            }
        }
    }
}

SCENARIO("Sliding sync room list uses the persistent store as the source of truth, not the runtime cache",
         "[sync][sliding-sync][room-list]")
{
    GIVEN("a joined room that exists only in the persistent store, not the runtime cache")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        // runtime.database.rooms is intentionally left empty to simulate a
        // stale or unhydrated runtime cache.

        auto store = merovingian::database::PersistentStore{};
        store.rooms = {
            {"!alpha:example.org", "@alice:example.org"},
        };
        store.memberships = {
            {"!alpha:example.org", "@alice:example.org", "join", 1U},
        };
        append_event(store, "$alpha-name", "!alpha:example.org", R"({"type":"m.room.name","content":{"name":"Alpha"}})",
                     1U);
        append_state(store, "!alpha:example.org", "m.room.name", "", "$alpha-name");

        auto list = merovingian::sync::SlidingSyncList{};
        list.ranges = {
            {0U, 9U}
        };
        list.sort = {"by_name"};

        WHEN("the room list is computed for Alice")
        {
            auto const result = merovingian::sync::compute_room_list(runtime, "@alice:example.org", list, {}, store);

            THEN("the room is still visible because the persistent store is authoritative")
            {
                REQUIRE(result.count == 1U);
                REQUIRE(result.windowed_room_ids == std::vector<std::string>{"!alpha:example.org"});
                REQUIRE(result.ops.size() == 1U);
                REQUIRE(result.ops.front().op == "SYNC");
                REQUIRE(result.ops.front().room_ids == std::vector<std::string>{"!alpha:example.org"});
            }
        }
    }
}

SCENARIO("Sliding sync extensions build scoped to-device e2ee account-data receipts and typing responses",
         "[sync][sliding-sync][extensions]")
{
    GIVEN("pending extension data across multiple sync surfaces")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.database.persistent_store.receipts = {
            {"!room-a:example.org", "m.read", "@alice:example.org", "$event-a",   111U, 3U},
            {"!room-b:example.org", "m.read", "@bob:example.org",   "$event-b",   222U, 4U},
            {"!room-a:example.org", "m.read", "@carol:example.org", "$event-old", 99U,  1U},
        };
        runtime.typing_users = {
            {"!room-a:example.org", "@alice:example.org", true,  1U},
            {"!room-b:example.org", "@bob:example.org",   true,  3U},
            {"!room-b:example.org", "@carol:example.org", false, 4U},
        };
        runtime.room_typing_stream_id = {
            {"!room-a:example.org", 1U},
            {"!room-b:example.org", 3U},
        };

        auto store = merovingian::database::PersistentStore{};
        // The receipts/typing extensions only serve rooms the caller has joined (CSAZ-1), so
        // alice is joined to both rooms the fixture reports on.
        store.memberships = {
            {"!room-a:example.org", "@alice:example.org", "join", 1U},
            {"!room-b:example.org", "@alice:example.org", "join", 2U},
        };
        REQUIRE(merovingian::database::enqueue_to_device_message(
            store, {0U, "@bob:example.org", "@alice:example.org", "ALICE", "m.room.encrypted", "{not-json"}));
        REQUIRE(merovingian::database::enqueue_to_device_message(
            store, {0U, "@bob:example.org", "@alice:example.org", "ALICE", "m.room_key", R"({"session":"two"})"}));

        store.device_list_changes = {
            {1U, "@alice:example.org", "@ignored:example.org", "changed"},
            {3U, "@alice:example.org", "@changed:example.org", "changed"},
            {4U, "@alice:example.org", "@left:example.org",    "left"   },
        };
        store.one_time_keys = {
            {"@alice:example.org", "ALICE", "signed_curve25519:AAAA", "{}"},
            {"@alice:example.org", "ALICE", "curve25519:BBBB",        "{}"},
        };
        store.fallback_keys = {
            {"@alice:example.org", "ALICE", "signed_curve25519:FFFF", "{}"},
            {"@alice:example.org", "ALICE", "signed_curve25519:GGGG", "{}"},
            {"@alice:example.org", "ALICE", "curve25519:HHHH",        "{}"},
        };
        store.account_data = {
            {"@alice:example.org", "",                    "m.push_rules", R"({"global":{"content":[]}})",     3U},
            {"@alice:example.org", "!room-a:example.org", "m.tag",        R"({"tags":{"m.favourite":{}}})",   4U},
            {"@alice:example.org", "!room-b:example.org", "m.tag",        R"({"tags":{"m.lowpriority":{}}})", 5U},
        };

        auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
        requests.to_device = merovingian::sync::ExtToDeviceRequest{true, 0U, std::optional<std::string>{"abc"}};
        requests.e2ee = merovingian::sync::ExtE2eeRequest{true};
        requests.account_data = merovingian::sync::ExtAccountDataRequest{true};
        requests.receipts = merovingian::sync::ExtReceiptsRequest{true, {}};
        requests.typing = merovingian::sync::ExtTypingRequest{true, {"!room-b:example.org"}};

        WHEN("the enabled extensions are built for the current response")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       2U, 2U, store, {"!room-a:example.org"});

            THEN("each extension returns only the expected scoped data")
            {
                REQUIRE(responses.to_device.has_value());
                REQUIRE(responses.to_device->events_json.size() == 2U);
                REQUIRE(responses.to_device->next_batch == "2");
                auto const invalid_to_device = parse_object(responses.to_device->events_json.front());
                REQUIRE(string_member(invalid_to_device, "type") != nullptr);
                REQUIRE(*string_member(invalid_to_device, "type") == "m.room.encrypted");
                auto const* invalid_content = object_member(invalid_to_device, "content");
                REQUIRE(invalid_content != nullptr);
                REQUIRE(invalid_content->empty());

                REQUIRE(responses.e2ee.has_value());
                REQUIRE(responses.e2ee->changed == std::vector<std::string>{"@changed:example.org"});
                REQUIRE(responses.e2ee->left == std::vector<std::string>{"@left:example.org"});
                REQUIRE(responses.e2ee->device_one_time_keys_count.at("signed_curve25519") == 1U);
                REQUIRE(responses.e2ee->device_one_time_keys_count.at("curve25519") == 1U);
                REQUIRE(responses.e2ee->device_unused_fallback_key_types ==
                        std::vector<std::string>{"signed_curve25519", "curve25519"});

                REQUIRE(responses.account_data.has_value());
                REQUIRE(responses.account_data->global_json.size() == 1U);
                REQUIRE(responses.account_data->rooms_json.size() == 1U);
                REQUIRE(responses.account_data->rooms_json.contains("!room-a:example.org"));
                REQUIRE_FALSE(responses.account_data->rooms_json.contains("!room-b:example.org"));

                REQUIRE(responses.receipts.has_value());
                REQUIRE(responses.receipts->rooms_json.size() == 1U);
                REQUIRE(responses.receipts->rooms_json.contains("!room-a:example.org"));
                REQUIRE_FALSE(responses.receipts->rooms_json.contains("!room-b:example.org"));
                // m.receipt is an EphemeralRoom-kind event (ruma's
                // SyncReceiptEvent): the wire shape is
                // {"type":"m.receipt","content":{...}}, not bare content.
                auto const receipt_event = parse_object(responses.receipts->rooms_json.at("!room-a:example.org"));
                REQUIRE(string_member(receipt_event, "type") != nullptr);
                REQUIRE(*string_member(receipt_event, "type") == "m.receipt");
                auto const* receipt_content = object_member(receipt_event, "content");
                REQUIRE(receipt_content != nullptr);
                REQUIRE(object_member(*receipt_content, "$event-a") != nullptr);

                REQUIRE(responses.typing.has_value());
                REQUIRE(responses.typing->rooms_json.size() == 1U);
                REQUIRE(responses.typing->rooms_json.contains("!room-b:example.org"));
                // m.typing is likewise an EphemeralRoom-kind event (ruma's
                // SyncTypingEvent): {"type":"m.typing","content":{"user_ids":...}}.
                auto const typing_event = parse_object(responses.typing->rooms_json.at("!room-b:example.org"));
                REQUIRE(string_member(typing_event, "type") != nullptr);
                REQUIRE(*string_member(typing_event, "type") == "m.typing");
                auto const* typing_content = object_member(typing_event, "content");
                REQUIRE(typing_content != nullptr);
                auto const* user_ids = array_member(*typing_content, "user_ids");
                REQUIRE(user_ids != nullptr);
                REQUIRE(user_ids->size() == 1U);
                auto const* typing_user = std::get_if<std::string>(&(*user_ids)[0].storage());
                REQUIRE(typing_user != nullptr);
                REQUIRE(*typing_user == "@bob:example.org");
            }
        }
    }
}

// Spec (C-S API, Room history visibility): a user needs to join a room to view events in it,
// and (Receipts) "Servers MUST NOT send the m.read.private receipt to any other user than the
// one which originally sent it". CSAZ-1 / CSAZ-4 at the extension builder.
// Account data is never signed, so its content may hold fractional numbers: m.tag's `order` is
// "A number in a range [0,1]". The account_data extension must deliver such content unchanged,
// not replace it with an empty object as the canonical-JSON parser would (PR #522 review).
SCENARIO("Sliding sync account_data extension delivers content holding fractional numbers",
         "[sync][sliding-sync][extensions][account-data]")
{
    GIVEN("a room tag whose order is 0.5")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};
        store.memberships = {
            {"!room-a:example.org", "@alice:example.org", "join", 1U},
        };
        store.account_data = {
            {"@alice:example.org", "!room-a:example.org", "m.tag", R"({"tags":{"m.favourite":{"order":0.5}}})", 4U},
        };
        auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
        requests.account_data = merovingian::sync::ExtAccountDataRequest{true};

        WHEN("the account_data extension is built")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       2U, 2U, store, {"!room-a:example.org"});

            THEN("the tag arrives with its order")
            {
                REQUIRE(responses.account_data.has_value());
                REQUIRE(responses.account_data->rooms_json.contains("!room-a:example.org"));
                auto const& events = responses.account_data->rooms_json.at("!room-a:example.org");
                REQUIRE(events.size() == 1U);
                auto const parsed = merovingian::canonicaljson::parse_json(events.front());
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* event = std::get_if<Object>(&parsed.value.storage());
                REQUIRE(event != nullptr);
                auto const* content = object_member(*event, "content");
                REQUIRE(content != nullptr);
                auto const* tags = object_member(*content, "tags");
                REQUIRE(tags != nullptr);
                auto const* favourite = object_member(*tags, "m.favourite");
                REQUIRE(favourite != nullptr);
                auto const* order = json_member(*favourite, "order");
                REQUIRE(order != nullptr);
                auto const* order_number = std::get_if<double>(&order->storage());
                REQUIRE(order_number != nullptr);
                REQUIRE(*order_number == 0.5);
            }
        }
    }
}

SCENARIO("Sliding sync receipts and typing extensions serve only joined rooms and visible receipts",
         "[sync][sliding-sync][extensions][security][csaz-1][csaz-4]")
{
    GIVEN("alice joined to one room, an outsider room she is not in, and receipts from bob and alice")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.database.persistent_store.receipts = {
            {"!joined:example.org",  "m.read",         "@bob:example.org",   "$bob-public",    10U, 5U},
            {"!joined:example.org",  "m.read.private", "@bob:example.org",   "$bob-private",   11U, 6U},
            {"!joined:example.org",  "m.fully_read",   "@bob:example.org",   "$bob-fully",     12U, 7U},
            {"!joined:example.org",  "m.read.private", "@alice:example.org", "$alice-private", 13U, 8U},
            {"!outside:example.org", "m.read",         "@bob:example.org",   "$outside",       14U, 9U},
        };
        runtime.typing_users = {
            {"!outside:example.org", "@bob:example.org", true, 0U},
        };
        runtime.room_typing_stream_id = {
            {"!outside:example.org", 4U},
        };
        auto store = merovingian::database::PersistentStore{};
        store.memberships = {
            {"!joined:example.org",  "@alice:example.org", "join",  1U},
            {"!outside:example.org", "@alice:example.org", "leave", 2U},
        };

        auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
        requests.receipts = merovingian::sync::ExtReceiptsRequest{
            true, {"!joined:example.org", "!outside:example.org"}
        };
        requests.typing = merovingian::sync::ExtTypingRequest{true, {"!outside:example.org"}};

        WHEN("the extensions are built for alice with rooms named explicitly")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       0U, 10U, store, {"!joined:example.org"});

            THEN("the room she has left is dropped from both extensions")
            {
                REQUIRE(responses.receipts.has_value());
                REQUIRE_FALSE(responses.receipts->rooms_json.contains("!outside:example.org"));
                REQUIRE(responses.typing.has_value());
                REQUIRE(responses.typing->rooms_json.empty());
            }

            THEN("in the joined room she sees bob's public receipt and her own private one only")
            {
                REQUIRE(responses.receipts->rooms_json.contains("!joined:example.org"));
                auto const event = parse_object(responses.receipts->rooms_json.at("!joined:example.org"));
                auto const* content = object_member(event, "content");
                REQUIRE(content != nullptr);
                REQUIRE(object_member(*content, "$bob-public") != nullptr);
                REQUIRE(object_member(*content, "$alice-private") != nullptr);
                REQUIRE(object_member(*content, "$bob-private") == nullptr);
                REQUIRE(object_member(*content, "$bob-fully") == nullptr);
            }
        }
    }
}

SCENARIO("Sliding sync collapses a repeated device-list subject to a single entry",
         "[sync][sliding-sync][extensions][device-lists]")
{
    GIVEN("a long-lived change log holding many rows for the same subject user")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};
        for (auto stream_id = std::uint64_t{1U}; stream_id <= 50U; ++stream_id)
        {
            store.device_list_changes.push_back({stream_id, "@alice:example.org", "@bob:example.org", "changed"});
        }
        store.one_time_keys = {
            {"@alice:example.org", "ALICE", "signed_curve25519:AAAA", "{}"},
        };

        auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
        requests.e2ee = merovingian::sync::ExtE2eeRequest{true};

        WHEN("the e2ee extension is built for an initial request")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       0U, 50U, store, {});

            THEN("the subject is reported once rather than once per change row")
            {
                // The initial response still reports the change — a freshly
                // logged-in device must know to /keys/query — but repeating the
                // same user ID for every row is what made these responses grow
                // into hundreds of kilobytes.
                REQUIRE(responses.e2ee.has_value());
                REQUIRE(responses.e2ee->changed == std::vector<std::string>{"@bob:example.org"});
                REQUIRE(responses.e2ee->left.empty());
            }

            THEN("one-time key counts are still reported alongside it")
            {
                REQUIRE(responses.e2ee.has_value());
                REQUIRE(responses.e2ee->device_one_time_keys_count.at("signed_curve25519") == 1U);
            }
        }

        WHEN("the e2ee extension is built for an incremental request")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       10U, 50U, store, {});

            THEN("the subject is still collapsed to a single entry")
            {
                REQUIRE(responses.e2ee.has_value());
                REQUIRE(responses.e2ee->changed == std::vector<std::string>{"@bob:example.org"});
            }
        }
    }
}

SCENARIO("Sliding sync room list ordering is fixed by the sort keys, not by the order events sit in the store",
         "[sliding-sync][sort][sp01]")
{
    GIVEN("eight joined rooms whose events are stored ascending, descending and shuffled by stream ordering")
    {
        auto ascending_events = sort_fixture_events();
        std::ranges::sort(ascending_events, {}, &SortFixtureEvent::stream_ordering);
        auto descending_events = ascending_events;
        std::ranges::reverse(descending_events);
        // A stride coprime with the 16 events is a deterministic permutation that is neither
        // ascending nor descending.
        auto shuffled_events = std::vector<SortFixtureEvent>{};
        for (auto i = std::size_t{0U}; i < ascending_events.size(); ++i)
        {
            shuffled_events.push_back(ascending_events[(i * 7U + 3U) % ascending_events.size()]);
        }

        auto const ascending = make_sort_fixture_store(ascending_events);
        auto const descending = make_sort_fixture_store(descending_events);
        auto const shuffled = make_sort_fixture_store(shuffled_events);
        auto const stores = std::vector<std::reference_wrapper<merovingian::database::PersistentStore const>>{
            ascending, descending, shuffled};

        REQUIRE(std::ranges::is_sorted(ascending.events, {}, &merovingian::database::PersistentEvent::stream_ordering));
        REQUIRE(std::ranges::is_sorted(descending.events, std::ranges::greater{},
                                       &merovingian::database::PersistentEvent::stream_ordering));
        REQUIRE_FALSE(
            std::ranges::is_sorted(shuffled.events, {}, &merovingian::database::PersistentEvent::stream_ordering));
        REQUIRE_FALSE(std::ranges::is_sorted(shuffled.events, std::ranges::greater{},
                                             &merovingian::database::PersistentEvent::stream_ordering));

        WHEN("rooms are sorted by recency counting only m.room.message events")
        {
            THEN("each room sorts by its newest message, ignoring newer events of other types, and ties go by room ID")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {"by_recency"}, {"m.room.message"}) ==
                            sort_fixture_rooms("dfbceagh"));
                }
            }
        }

        WHEN("rooms are sorted by recency with no bump event types")
        {
            THEN("every event type counts, so each room sorts by its newest event of any type")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {"by_recency"}, {}) == sort_fixture_rooms("agedfcbh"));
                }
            }
        }

        WHEN("rooms are sorted by recency with two bump event types")
        {
            THEN("an event of either listed type bumps the room, and an unlisted type does not")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {"by_recency"}, {"m.room.message", "m.room.topic"}) ==
                            sort_fixture_rooms("agedfcbh"));
                    REQUIRE(sorted_rooms(store.get(), {"by_recency"}, {"m.room.topic"}) ==
                            sort_fixture_rooms("agechbdf"));
                }
            }
        }

        WHEN("rooms are sorted by name")
        {
            THEN("named rooms come first in lexicographic order, equal names go by room ID, unnamed rooms last")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {"by_name"}, {}) == sort_fixture_rooms("bdfahceg"));
                }
            }
        }

        WHEN("rooms are sorted by recency and then by name")
        {
            THEN("the name only breaks ties in recency")
            {
                for (auto const& store : stores)
                {
                    // g and h have no message, so they tie on recency; h is named and so precedes g.
                    REQUIRE(sorted_rooms(store.get(), {"by_recency", "by_name"}, {"m.room.message"}) ==
                            sort_fixture_rooms("dfbceahg"));
                }
            }
        }

        WHEN("rooms are sorted by name and then by recency")
        {
            THEN("recency only breaks ties in name, so equal names and unnamed rooms order by newest message")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {"by_name", "by_recency"}, {"m.room.message"}) ==
                            sort_fixture_rooms("dbfahceg"));
                }
            }
        }

        WHEN("rooms are sorted with no sort key")
        {
            THEN("rooms order by room ID")
            {
                for (auto const& store : stores)
                {
                    REQUIRE(sorted_rooms(store.get(), {}, {}) == sort_fixture_rooms("abcdefgh"));
                }
            }
        }
    }
}

// Security audit run-1 (sp01.sliding-sync-extension-rooms-unbounded): receipts and typing are now
// read in one pass over their tables, grouped by the joined rooms that were asked for. Each room
// must still get exactly its own entries, with the since-position, ignored-sender and typing
// rules applied as before, and the handler's shared-index overload must give the same answer.
SCENARIO("Sliding sync receipts and typing group one pass of their tables into the right rooms",
         "[sync][sliding-sync][extensions][security][sp01]")
{
    GIVEN("alice joined to two rooms whose receipts and typing entries are interleaved in storage")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.database.persistent_store.receipts = {
            {"!a:example.org", "m.read", "@bob:example.org",     "$a-bob",     10U, 5U},
            {"!b:example.org", "m.read", "@carol:example.org",   "$b-carol",   11U, 6U},
            {"!a:example.org", "m.read", "@carol:example.org",   "$a-carol",   12U, 7U},
            {"!b:example.org", "m.read", "@bob:example.org",     "$b-old",     13U, 2U},
            {"!a:example.org", "m.read", "@mallory:example.org", "$a-ignored", 14U, 8U},
        };
        runtime.typing_users = {
            {"!b:example.org", "@carol:example.org",   true,  0U},
            {"!a:example.org", "@bob:example.org",     true,  0U},
            {"!a:example.org", "@dave:example.org",    false, 0U},
            {"!a:example.org", "@mallory:example.org", true,  0U},
        };
        runtime.room_typing_stream_id = {
            {"!a:example.org", 9U},
            {"!b:example.org", 3U},
        };
        auto store = merovingian::database::PersistentStore{};
        store.memberships = {
            {"!a:example.org", "@alice:example.org", "join", 1U},
            {"!b:example.org", "@alice:example.org", "join", 2U},
        };
        auto const ignored = std::unordered_set<std::string>{"@mallory:example.org"};

        auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
        requests.receipts = merovingian::sync::ExtReceiptsRequest{
            true, {"!a:example.org", "!b:example.org"}
        };
        requests.typing = merovingian::sync::ExtTypingRequest{
            true, {"!a:example.org", "!b:example.org"}
        };

        WHEN("the extensions are built from position 4")
        {
            auto const responses = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE", requests,
                                                                       4U, 10U, store, {}, ignored);

            THEN("each room's receipts are its own, newer than the position, and not from the ignored user")
            {
                REQUIRE(responses.receipts.has_value());
                REQUIRE(responses.receipts->rooms_json.size() == 2U);
                auto const a = parse_object(responses.receipts->rooms_json.at("!a:example.org"));
                auto const* a_content = object_member(a, "content");
                REQUIRE(a_content != nullptr);
                REQUIRE(a_content->size() == 2U);
                REQUIRE(object_member(*a_content, "$a-bob") != nullptr);
                REQUIRE(object_member(*a_content, "$a-carol") != nullptr);
                auto const b = parse_object(responses.receipts->rooms_json.at("!b:example.org"));
                auto const* b_content = object_member(b, "content");
                REQUIRE(b_content != nullptr);
                REQUIRE(b_content->size() == 1U);
                REQUIRE(object_member(*b_content, "$b-carol") != nullptr);
            }

            THEN("only the room whose typing changed after the position is reported, with its typing users")
            {
                REQUIRE(responses.typing.has_value());
                REQUIRE(responses.typing->rooms_json.size() == 1U);
                auto const a = parse_object(responses.typing->rooms_json.at("!a:example.org"));
                auto const* content = object_member(a, "content");
                REQUIRE(content != nullptr);
                auto const* user_ids = array_member(*content, "user_ids");
                REQUIRE(user_ids != nullptr);
                REQUIRE(user_ids->size() == 1U);
                REQUIRE(std::get<std::string>(user_ids->front().storage()) == "@bob:example.org");
            }

            THEN("the overload taking the handler's room-access index gives the same responses")
            {
                auto const index = merovingian::sync::room_access_index(store, "@alice:example.org");
                auto const shared = merovingian::sync::build_extensions(runtime, "@alice:example.org", "ALICE",
                                                                        requests, 4U, 10U, store, index, {}, ignored);
                REQUIRE(shared.receipts.has_value());
                REQUIRE(shared.typing.has_value());
                REQUIRE(shared.receipts->rooms_json == responses.receipts->rooms_json);
                REQUIRE(shared.typing->rooms_json == responses.typing->rooms_json);
            }
        }
    }
}
