// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// HF-B S1: `to_device_messages.stream_id` is a TEXT column, so ORDER BY puts
// "10" before "9". A store reloaded after a restart held the queue out of
// numeric order, and the sliding sync to_device extension, which takes the first
// `limit` messages and sets next_batch to the last one it included, then
// acknowledged (and deleted) a row it never delivered: a lost room key.
//
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#extensions-to-sync
// (to-device messages are delivered once, and the `next_batch` of /sync
// acknowledges only what the response carried) and MSC4186 to_device pagination.
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/sync/SlidingSyncExtensions.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

namespace
{
namespace db = merovingian::database;
namespace cj = merovingian::canonicaljson;

class DatabaseScratch final
{
public:
    DatabaseScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-todevice-order-XXXXXX").string();
        auto const* made = ::mkdtemp(pattern.data());
        if (made == nullptr)
        {
            throw std::runtime_error{"temporary directory unavailable"};
        }
        path = made;
    }
    DatabaseScratch(DatabaseScratch const&) = delete;
    auto operator=(DatabaseScratch const&) -> DatabaseScratch& = delete;
    ~DatabaseScratch()
    {
        auto ec = std::error_code{};
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

[[nodiscard]] auto ordinal_of(std::string const& event_json) -> std::int64_t
{
    auto const parsed = cj::parse_lossless(event_json);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* event = std::get_if<cj::Object>(&parsed.value.storage());
    REQUIRE(event != nullptr);
    for (auto const& member : *event)
    {
        if (member.key != "content")
        {
            continue;
        }
        auto const* content = std::get_if<cj::Object>(&member.value->storage());
        REQUIRE(content != nullptr);
        for (auto const& field : *content)
        {
            if (field.key == "ordinal")
            {
                auto const* number = std::get_if<std::int64_t>(&field.value->storage());
                REQUIRE(number != nullptr);
                return *number;
            }
        }
    }
    FAIL("event has no content.ordinal");
    return -1;
}

[[nodiscard]] auto page(merovingian::homeserver::HomeserverRuntime const& runtime, db::PersistentStore& store,
                        std::uint32_t limit, std::string_view since) -> merovingian::sync::ExtToDeviceResponse
{
    auto requests = merovingian::sync::SlidingSyncExtensionRequests{};
    requests.to_device = merovingian::sync::ExtToDeviceRequest{true, limit, std::string{since}};
    auto const responses = merovingian::sync::build_extensions(runtime, "@bob:example.org", "BOB_DEVICE", requests, 0U,
                                                               store.next_sync_stream_id, store, {});
    REQUIRE(responses.to_device.has_value());
    return *responses.to_device;
}

[[nodiscard]] auto enqueue(db::PersistentStore& store, std::int64_t ordinal) -> bool
{
    return db::enqueue_to_device_message(store,
                                         {0U, "@alice:example.org", "@bob:example.org", "BOB_DEVICE", "m.test.message",
                                          std::string{"{\"ordinal\":"} + std::to_string(ordinal) + "}"});
}

[[nodiscard]] auto stream_ids_ascend(db::PersistentStore const& store) -> bool
{
    return std::ranges::is_sorted(store.to_device_messages, {}, &db::PersistentToDeviceMessage::stream_id);
}
} // namespace

SCENARIO("A reloaded to-device queue is delivered once, in order, across a digit boundary",
         "[sync][database][to-device-order]")
{
    GIVEN("a SQLite store whose queue holds stream ids 9, 10, 11 and 12 after a restart")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        {
            auto opened = db::open_sqlite_persistent_store(path);
            REQUIRE(opened.ok);
            REQUIRE(db::store_user(opened.store, {"@bob:example.org", "password-hash:v1:1", false, false, false}));
            REQUIRE(db::store_device(opened.store, {"@bob:example.org", "BOB_DEVICE", "Bob's device"}));
            for (auto ordinal = std::int64_t{1}; ordinal <= 12; ++ordinal)
            {
                REQUIRE(enqueue(opened.store, ordinal));
            }
            // Acknowledge the first eight, as a client that has seen them would.
            auto const acknowledged = db::drain_to_device_messages(opened.store, "@bob:example.org", "BOB_DEVICE", 8U,
                                                                   opened.store.next_sync_stream_id);
            REQUIRE(acknowledged.size() == 4U);
            REQUIRE(opened.store.to_device_messages.size() == 4U);
        }
        auto reopened = db::open_sqlite_persistent_store(path);
        REQUIRE(reopened.ok);

        WHEN("the store is reloaded")
        {
            THEN("the queue is held in numeric stream-id order")
            {
                REQUIRE(reopened.store.to_device_messages.size() == 4U);
                REQUIRE(stream_ids_ascend(reopened.store));
            }
        }

        WHEN("Bob pages through it two messages at a time, following each next_batch")
        {
            auto delivered = std::vector<std::int64_t>{};
            auto since = std::string{"8"};
            for (auto round = 0; round < 6; ++round)
            {
                auto const response = page(runtime, reopened.store, 2U, since);
                for (auto const& event : response.events_json)
                {
                    delivered.push_back(ordinal_of(event));
                }
                since = response.next_batch;
            }

            THEN("every message arrives exactly once, in order, and the queue is then empty")
            {
                REQUIRE(delivered == std::vector<std::int64_t>{9, 10, 11, 12});
                REQUIRE(reopened.store.to_device_messages.empty());
            }
        }
    }
}

SCENARIO("The sliding sync to_device extension never acknowledges a row it did not deliver",
         "[sync][security][to-device-order]")
{
    GIVEN("a store whose queue is held out of stream-id order, as a text-sorted reload left it")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = db::PersistentStore{};
        REQUIRE(db::store_user(store, {"@bob:example.org", "password-hash:v1:1", false, false, false}));
        REQUIRE(db::store_device(store, {"@bob:example.org", "BOB_DEVICE", "Bob's device"}));
        for (auto ordinal = std::int64_t{1}; ordinal <= 5; ++ordinal)
        {
            REQUIRE(enqueue(store, ordinal));
        }
        std::ranges::reverse(store.to_device_messages);
        REQUIRE_FALSE(stream_ids_ascend(store));

        WHEN("Bob asks for two messages at a time")
        {
            auto delivered = std::vector<std::int64_t>{};
            auto since = std::string{"0"};
            auto acknowledged_undelivered = false;
            for (auto round = 0; round < 5; ++round)
            {
                auto const response = page(runtime, store, 2U, since);
                for (auto const& event : response.events_json)
                {
                    delivered.push_back(ordinal_of(event));
                }
                // Every row at or below next_batch must already have been delivered.
                auto const next = static_cast<std::int64_t>(std::stoull(response.next_batch));
                for (auto ordinal = std::int64_t{1}; ordinal <= next && ordinal <= 5; ++ordinal)
                {
                    if (std::ranges::find(delivered, ordinal) == delivered.end())
                    {
                        acknowledged_undelivered = true;
                    }
                }
                since = response.next_batch;
            }

            THEN("each message is delivered once, in order, and none is acknowledged before it was delivered")
            {
                REQUIRE_FALSE(acknowledged_undelivered);
                REQUIRE(delivered == std::vector<std::int64_t>{1, 2, 3, 4, 5});
            }
        }

        WHEN("the queue is drained")
        {
            auto const drained =
                db::drain_to_device_messages(store, "@bob:example.org", "BOB_DEVICE", 0U, store.next_sync_stream_id);

            THEN("the messages come back in stream-id order whatever order the store holds")
            {
                REQUIRE(drained.size() == 5U);
                REQUIRE(std::ranges::is_sorted(drained, {}, &db::PersistentToDeviceMessage::stream_id));
            }
        }
    }
}
