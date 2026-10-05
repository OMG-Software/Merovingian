// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync_extensions.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;

[[nodiscard]] auto member(Object const& object, std::string_view name) -> Value const*
{
    for (auto const& entry : object)
    {
        if (entry.key == name)
        {
            return entry.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto object_value(Value const* value) -> Object const*
{
    return value != nullptr ? std::get_if<Object>(&value->storage()) : nullptr;
}

[[nodiscard]] auto event_ordinals(std::vector<std::string> const& events) -> std::vector<std::int64_t>
{
    auto ordinals = std::vector<std::int64_t>{};
    for (auto const& json : events)
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* event = std::get_if<Object>(&parsed.value.storage());
        REQUIRE(event != nullptr);
        auto const* content = object_value(member(*event, "content"));
        REQUIRE(content != nullptr);
        auto const* ordinal = member(*content, "ordinal");
        REQUIRE(ordinal != nullptr);
        auto const* integer = std::get_if<std::int64_t>(&ordinal->storage());
        REQUIRE(integer != nullptr);
        ordinals.push_back(*integer);
    }
    return ordinals;
}

[[nodiscard]] auto ordinal_sequence(std::int64_t first, std::int64_t last) -> std::vector<std::int64_t>
{
    auto ordinals = std::vector<std::int64_t>{};
    for (auto value = first; value <= last; ++value)
    {
        ordinals.push_back(value);
    }
    return ordinals;
}

[[nodiscard]] auto to_device_page(merovingian::homeserver::HomeserverRuntime const& runtime,
                                  merovingian::database::PersistentStore& store,
                                  std::string_view since) -> merovingian::sync::ExtToDeviceResponse
{
    auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
    requests.to_device = merovingian::sync::ExtToDeviceRequest{true, 20U, std::string{since}};
    auto const responses = merovingian::sync::build_extensions(runtime, "@bob:example.org", "BOB_DEVICE", requests, 0U,
                                                               store.next_sync_stream_id - 1U, store, {});
    REQUIRE(responses.to_device.has_value());
    return *responses.to_device;
}

} // namespace

// MSC4186 to_device extension pagination: the continuation position must not
// advance beyond messages actually included in this response. The global sync
// watermark may also advance for unrelated surfaces such as presence.
SCENARIO("sliding sync to_device pages advance only past messages included in the response",
         "[sync][security][security_audit_to_device_pagination]")
{
    GIVEN("a unit-memory store has Bob's active account and device, 45 queued messages, and unrelated presence "
          "advances the global watermark")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(
            merovingian::database::store_user(store, {"@bob:example.org", "password-hash:v1:1", false, false, false}));
        REQUIRE(merovingian::database::store_device(store, {"@bob:example.org", "BOB_DEVICE", "Bob's device"}));
        for (auto ordinal = std::int64_t{1}; ordinal <= 45; ++ordinal)
        {
            auto const content = std::string{"{\"ordinal\":"} + std::to_string(ordinal) + "}";
            REQUIRE(merovingian::database::enqueue_to_device_message(
                store, {0U, "@alice:example.org", "@bob:example.org", "BOB_DEVICE", "m.test.message", content}));
        }
        REQUIRE(store.to_device_messages.size() == 45U);
        REQUIRE(merovingian::database::upsert_presence(
            store, {0U, "@bob:example.org", "online", "unrelated sync activity", 0, true}));
        REQUIRE(merovingian::database::upsert_presence(
            store, {0U, "@bob:example.org", "online", "later unrelated sync activity", 0, true}));
        REQUIRE(store.next_sync_stream_id - 1U > store.to_device_messages.back().stream_id);

        WHEN("Bob retries the first page after losing it, then follows each returned next_batch")
        {
            auto const first = to_device_page(runtime, store, "0");
            auto const rows_after_first = store.to_device_messages.size();
            auto const retry = to_device_page(runtime, store, "0");
            auto const rows_after_retry = store.to_device_messages.size();
            auto const second = to_device_page(runtime, store, first.next_batch);
            auto const rows_after_second = store.to_device_messages.size();
            auto const third = to_device_page(runtime, store, second.next_batch);
            auto const rows_after_third = store.to_device_messages.size();
            auto const first_remaining_stream_id =
                store.to_device_messages.empty()
                    ? std::optional<std::uint64_t>{}
                    : std::optional<std::uint64_t>{store.to_device_messages.front().stream_id};
            auto const empty = to_device_page(runtime, store, third.next_batch);
            auto const rows_after_empty = store.to_device_messages.size();

            THEN("each page is complete, a lost response is replayed, and only acknowledged rows are removed")
            {
                REQUIRE(first.events_json.size() == 20U);
                REQUIRE(first.next_batch == "20");
                REQUIRE(event_ordinals(first.events_json) == ordinal_sequence(1, 20));
                REQUIRE(rows_after_first == 45U);

                REQUIRE(retry.events_json == first.events_json);
                REQUIRE(retry.next_batch == first.next_batch);
                REQUIRE(rows_after_retry == 45U);

                REQUIRE(second.events_json.size() == 20U);
                REQUIRE(second.next_batch == "40");
                REQUIRE(event_ordinals(second.events_json) == ordinal_sequence(21, 40));
                REQUIRE(rows_after_second == 25U);

                REQUIRE(third.events_json.size() == 5U);
                REQUIRE(third.next_batch == "45");
                REQUIRE(event_ordinals(third.events_json) == std::vector<std::int64_t>{41, 42, 43, 44, 45});
                REQUIRE(rows_after_third == 5U);
                REQUIRE(first_remaining_stream_id.has_value());
                REQUIRE(*first_remaining_stream_id == 41U);

                REQUIRE(empty.events_json.empty());
                REQUIRE(empty.next_batch == third.next_batch);
                REQUIRE(rows_after_empty == 0U);
            }
        }
    }
}
