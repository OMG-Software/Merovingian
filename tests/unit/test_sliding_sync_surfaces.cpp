// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync_extensions.hpp"
#include "merovingian/sync/sliding_sync_room_list.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
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

        append_event(store, "$alpha-message", "!alpha:example.org",
                     R"({"type":"m.room.message","content":{"body":"alpha"}})", 4U);
        append_event(store, "$beta-message-1", "!beta:example.org",
                     R"({"type":"m.room.message","content":{"body":"beta-1"}})", 5U);
        append_event(store, "$beta-message-2", "!beta:example.org",
                     R"({"type":"m.room.message","content":{"body":"beta-2"}})", 6U);
        append_event(store, "$gamma-encrypted", "!gamma:example.org",
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

SCENARIO("Sliding sync extensions build scoped to-device e2ee account-data receipts and typing responses",
         "[sync][sliding-sync][extensions]")
{
    GIVEN("pending extension data across multiple sync surfaces")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.receipts = {
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
                auto const receipt_content = parse_object(responses.receipts->rooms_json.at("!room-a:example.org"));
                REQUIRE(object_member(receipt_content, "$event-a") != nullptr);

                REQUIRE(responses.typing.has_value());
                REQUIRE(responses.typing->rooms_json.size() == 1U);
                REQUIRE(responses.typing->rooms_json.contains("!room-b:example.org"));
                auto const typing_content = parse_object(responses.typing->rooms_json.at("!room-b:example.org"));
                auto const* user_ids = array_member(typing_content, "user_ids");
                REQUIRE(user_ids != nullptr);
                REQUIRE(user_ids->size() == 1U);
                auto const* typing_user = std::get_if<std::string>(&(*user_ids)[0].storage());
                REQUIRE(typing_user != nullptr);
                REQUIRE(*typing_user == "@bob:example.org");
            }
        }
    }
}
