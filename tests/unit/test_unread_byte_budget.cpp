// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C05 (ADR-0655): one unread count of one room parses at most max_unread_bytes_parsed bytes of event
// JSON, the events it classifies and the parents it follows, so a member who posts large events cannot make every other
// member's /sync parse a thousand of them. Under the budget the counts are exact.
//
// Spec: client-server-api.md, "Marking notifications as read": notifications after the read receipt are unread.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/ReadMarkers.hpp"
#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"
#include "merovingian/sync/UnreadEventClassifier.hpp"
#include "merovingian/sync/UnreadEventOutcome.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace
{

namespace db = merovingian::database;
namespace sync = merovingian::sync;

constexpr auto room = std::string_view{"!room:example.org"};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};
// sync::max_unread_bytes_parsed, named here as a number so that a change to it is a change to this test.
constexpr auto byte_budget = std::size_t{524288U};

class EveryMessageNotifies final : public sync::UnreadEventClassifier
{
public:
    [[nodiscard]] auto counted_after(std::string_view /*room_id*/) -> std::optional<std::uint64_t> override
    {
        return 0U;
    }

    [[nodiscard]] auto classify(std::string_view /*room_id*/, merovingian::canonicaljson::Value const& /*event*/)
        -> sync::UnreadEventOutcome override
    {
        return {true, false};
    }

    [[nodiscard]] auto visible(db::PersistentEvent const& /*event*/) -> bool override
    {
        return true;
    }
};

// A message of bob's whose JSON is exactly `size` bytes.
[[nodiscard]] auto message_of_size(std::size_t size, std::string_view relation = {}) -> std::string
{
    auto const head = std::string{R"({"type":"m.room.message","sender":"@bob:example.org","content":{)"} +
                      std::string{relation} + R"("body":")";
    auto const tail = std::string{R"("}})"};
    REQUIRE(size > head.size() + tail.size());
    return head + std::string(size - head.size() - tail.size(), 'x') + tail;
}

auto add_event(db::PersistentStore& store, std::string const& event_id, std::string json, std::uint64_t ordering)
    -> void
{
    store.events.push_back({event_id, std::string{room}, std::string{bob}, std::move(json), 1U, ordering, {}, {}, {}});
}

} // namespace

SCENARIO("an unread count parses a bounded number of bytes", "[sync][unread][c05][security]")
{
    GIVEN("two hundred nearly maximum-size messages the reader has not read")
    {
        auto store = db::PersistentStore{};
        for (auto ordering = std::uint64_t{1U}; ordering <= 200U; ++ordering)
        {
            add_event(store, "$big" + std::to_string(ordering), message_of_size(60000U), ordering);
        }

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{};
            auto const counts = sync::count_unread_by_thread(store, room, alice, sync::ReadMarkers{}, classifier);

            THEN("only as many of the newest as fit the byte budget are counted")
            {
                REQUIRE(counts.total().notification_count == byte_budget / 60000U);
            }
        }
    }

    GIVEN("exactly as many 1 KiB messages as the byte budget holds")
    {
        auto store = db::PersistentStore{};
        auto const fits = byte_budget / 1024U;
        for (auto ordering = std::uint64_t{1U}; ordering <= fits; ++ordering)
        {
            add_event(store, "$k" + std::to_string(ordering), message_of_size(1024U), ordering);
        }

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{};
            auto const counts = sync::count_unread_by_thread(store, room, alice, sync::ReadMarkers{}, classifier);

            THEN("every message is counted")
            {
                REQUIRE(counts.total().notification_count == fits);
            }
        }

        WHEN("one more message arrives")
        {
            add_event(store, "$over", message_of_size(1024U), fits + 1U);
            auto classifier = EveryMessageNotifies{};
            auto const counts = sync::count_unread_by_thread(store, room, alice, sync::ReadMarkers{}, classifier);

            THEN("the count is the budget's worth, a lower bound")
            {
                REQUIRE(counts.total().notification_count == fits);
            }
        }
    }

    GIVEN("three hundred ordinary small messages")
    {
        auto store = db::PersistentStore{};
        for (auto ordering = std::uint64_t{1U}; ordering <= 300U; ++ordering)
        {
            add_event(store, "$s" + std::to_string(ordering), message_of_size(200U), ordering);
        }

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{};
            auto const counts = sync::count_unread_by_thread(store, room, alice, sync::ReadMarkers{}, classifier);

            THEN("the count is exact")
            {
                REQUIRE(counts.total().notification_count == 300U);
            }
        }
    }
}

SCENARIO("following a relation to a large parent spends the byte budget", "[sync][unread][c05][security]")
{
    GIVEN("a large parent that belongs to a thread, and an event that references it")
    {
        auto store = db::PersistentStore{};
        add_event(store, "$parent",
                  message_of_size(60000U, R"("m.relates_to":{"rel_type":"m.thread","event_id":"$root"},)"), 1U);
        auto const child_json =
            std::string{R"({"type":"m.room.message","sender":"@bob:example.org","content":{"body":"c",)"
                        R"("m.relates_to":{"rel_type":"m.reference","event_id":"$parent"}}})"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(child_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const& child = std::get<merovingian::canonicaljson::Object>(parsed.value.storage());

        WHEN("the thread is looked up with room for the parent")
        {
            auto bytes_left = std::size_t{100000U};
            auto const thread = sync::event_thread_id(store, child, &bytes_left);

            THEN("the parent is parsed and charged")
            {
                REQUIRE(thread == "$root");
                REQUIRE(bytes_left == 100000U - store.events.find("$parent")->json.size());
            }
        }

        WHEN("the thread is looked up with too little budget left for the parent")
        {
            auto bytes_left = std::size_t{40000U};
            auto const thread = sync::event_thread_id(store, child, &bytes_left);

            THEN("the parent is not parsed and the event is in the main timeline")
            {
                REQUIRE(thread == "main");
                REQUIRE(bytes_left == 40000U);
            }
        }

        WHEN("the thread is looked up without a budget")
        {
            THEN("the lookup is unchanged")
            {
                REQUIRE(sync::event_thread_id(store, child) == "$root");
            }
        }
    }
}
