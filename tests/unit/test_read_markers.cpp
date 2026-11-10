// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/ReadMarkers.hpp"
#include "merovingian/sync/UnreadEventClassifier.hpp"
#include "merovingian/sync/UnreadEventOutcome.hpp"
#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace
{

auto add_event(merovingian::database::PersistentStore& store, std::string const& event_id, std::string const& json,
               std::uint64_t stream_ordering) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = "!room:example.org";
    event.sender_user_id = "@bob:example.org";
    event.json = json;
    event.stream_ordering = stream_ordering;
    store.events.push_back(std::move(event));
}

[[nodiscard]] auto thread_of(merovingian::database::PersistentStore const& store, std::string const& json)
    -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return merovingian::sync::event_thread_id(store, *object);
}

[[nodiscard]] auto relates_to(std::string const& rel_type, std::string const& event_id) -> std::string
{
    return R"({"type":"m.room.message","content":{"body":"x","m.relates_to":{"rel_type":")" + rel_type +
           R"(","event_id":")" + event_id + R"("}}})";
}

} // namespace

// Spec: Client-Server API, "Threaded read receipts": an event is in a thread if "It has a rel_type
// of m.thread, or Following the event relationships, it has a parent event which references the
// thread root with a rel_type of m.thread"; "Thread roots are considered to be in the main
// timeline, as are events that are related to a thread root via non-thread relations."
SCENARIO("event_thread_id places an event in its thread or the main timeline", "[sync][read-markers]")
{
    GIVEN("a thread root and a reply in its thread")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const root_json = std::string{R"({"type":"m.room.message","content":{"body":"root"}})"};
        add_event(store, "$root", root_json, 1U);
        add_event(store, "$reply", relates_to("m.thread", "$root"), 2U);

        THEN("the root and an unrelated event are in the main timeline")
        {
            REQUIRE(thread_of(store, root_json) == "main");
        }
        THEN("the reply is in the root's thread")
        {
            REQUIRE(thread_of(store, relates_to("m.thread", "$root")) == "$root");
        }
        THEN("an edit of the reply is in the root's thread, found through its parent")
        {
            REQUIRE(thread_of(store, relates_to("m.replace", "$reply")) == "$root");
        }
        THEN("a reaction to the root itself is in the main timeline")
        {
            REQUIRE(thread_of(store, relates_to("m.annotation", "$root")) == "main");
        }
        THEN("an event related to an event this server does not hold is in the main timeline")
        {
            REQUIRE(thread_of(store, relates_to("m.annotation", "$unknown")) == "main");
        }
    }

    GIVEN("a chain of non-thread relations four hops from a thread reply")
    {
        auto store = merovingian::database::PersistentStore{};
        add_event(store, "$reply", relates_to("m.thread", "$root"), 1U);
        add_event(store, "$a", relates_to("m.reference", "$reply"), 2U);
        add_event(store, "$b", relates_to("m.reference", "$a"), 3U);
        add_event(store, "$c", relates_to("m.reference", "$b"), 4U);

        THEN("three hops still reach the thread")
        {
            REQUIRE(thread_of(store, relates_to("m.reference", "$a")) == "$root");
            REQUIRE(thread_of(store, relates_to("m.reference", "$b")) == "$root");
        }
        THEN("the search stops after three hops, as the spec recommends")
        {
            REQUIRE(thread_of(store, relates_to("m.reference", "$c")) == "main");
        }
    }
}

// Spec: Client-Server API, "Marking notifications as read": the more recent of m.read and
// m.read.private counts, an unthreaded receipt covers every earlier event, and a threaded receipt
// covers only its own thread.
SCENARIO("read_markers_for builds the user's read positions from their receipts", "[sync][read-markers]")
{
    GIVEN("three events and receipts from alice and bob")
    {
        auto store = merovingian::database::PersistentStore{};
        add_event(store, "$e1", R"({"type":"m.room.message","content":{}})", 10U);
        add_event(store, "$e2", R"({"type":"m.room.message","content":{}})", 20U);
        add_event(store, "$e3", R"({"type":"m.room.message","content":{}})", 30U);
        auto receipts = std::vector<merovingian::database::PersistentReceipt>{
            {"!room:example.org",  "m.read",         "@alice:example.org", "$e1", 0U, 1U, {}     },
            {"!room:example.org",  "m.read.private", "@alice:example.org", "$e2", 0U, 2U, {}     },
            {"!room:example.org",  "m.read",         "@alice:example.org", "$e3", 0U, 3U, "$root"},
            {"!room:example.org",  "m.fully_read",   "@alice:example.org", "$e3", 0U, 4U, {}     },
            {"!room:example.org",  "m.read",         "@bob:example.org",   "$e3", 0U, 5U, {}     },
            {"!other:example.org", "m.read",         "@alice:example.org", "$e3", 0U, 6U, {}     },
        };

        WHEN("alice's markers in the room are built")
        {
            auto const markers =
                merovingian::sync::read_markers_for(receipts, store, "!room:example.org", "@alice:example.org");

            THEN("the unthreaded position is the further of her m.read and m.read.private receipts")
            {
                REQUIRE(markers.unthreaded == 20U);
            }
            THEN("her threaded receipt is a separate position for its thread only")
            {
                REQUIRE(markers.threads.size() == 1U);
                REQUIRE(markers.threads.at("$root") == 30U);
                REQUIRE(markers.covers(30U, "$root"));
                REQUIRE_FALSE(markers.covers(30U, "main"));
                REQUIRE(markers.covers(20U, "main"));
            }
        }

        WHEN("a user with no receipts asks")
        {
            auto const markers =
                merovingian::sync::read_markers_for(receipts, store, "!room:example.org", "@carol:example.org");

            THEN("nothing is covered")
            {
                REQUIRE(markers.unthreaded == 0U);
                REQUIRE(markers.threads.empty());
                REQUIRE_FALSE(markers.covers(10U, "main"));
            }
        }
    }
}

// Spec: Client-Server API, "Marking notifications as read": the read receipt is updated "either by
// using the API or by sending an event". ADR-0170: an event the user sends reads its own thread up
// to itself, and state events (which the server may send for the user) do not count.
SCENARIO("read_markers_for counts the user's own non-state events as reading their thread",
         "[sync][read-markers][own-event-read]")
{
    GIVEN("a room where alice has sent a message, a thread reply and a state event")
    {
        auto store = merovingian::database::PersistentStore{};
        add_event(store, "$root", R"({"type":"m.room.message","content":{"body":"root"}})", 10U);
        add_event(store, "$alice_main", R"({"type":"m.room.message","content":{"body":"hi"}})", 20U);
        add_event(store, "$alice_thread", relates_to("m.thread", "$root"), 30U);
        add_event(store, "$alice_state", R"({"type":"m.room.member","state_key":"@alice:example.org","content":{}})",
                  40U);
        for (auto event = store.events.begin(); event != store.events.end(); ++event)
        {
            if (event->event_id != "$root")
            {
                store.events.modify(event, [](merovingian::database::PersistentEvent& row) {
                    row.sender_user_id = "@alice:example.org";
                });
            }
        }

        WHEN("alice's markers are built with no receipts at all")
        {
            auto const markers =
                merovingian::sync::read_markers_for({}, store, "!room:example.org", "@alice:example.org");

            THEN("her message reads the main timeline and her reply reads the thread, each up to itself")
            {
                REQUIRE(markers.unthreaded == 0U);
                REQUIRE(markers.threads.size() == 2U);
                REQUIRE(markers.threads.at("main") == 20U);
                REQUIRE(markers.threads.at("$root") == 30U);
            }
            THEN("her state event, the latest of all, moves nothing")
            {
                REQUIRE_FALSE(markers.covers(40U, "main"));
            }
        }
    }
}

namespace
{

// Counts every event as a notification and records which events it was asked to judge.
class RecordingClassifier final : public merovingian::sync::UnreadEventClassifier
{
public:
    [[nodiscard]] auto counted_after(std::string_view /*room_id*/) -> std::optional<std::uint64_t> override
    {
        return std::uint64_t{0U};
    }
    [[nodiscard]] auto visible(merovingian::database::PersistentEvent const& event) -> bool override
    {
        asked.insert(event.event_id);
        return true;
    }
    [[nodiscard]] auto classify(std::string_view /*room_id*/, merovingian::canonicaljson::Value const& /*event*/)
        -> merovingian::sync::UnreadEventOutcome override
    {
        return {true, false};
    }

    std::unordered_set<std::string> asked{};
};

auto add_room_event(merovingian::database::PersistentStore& store, std::string const& event_id,
                    std::string const& room_id, std::string const& sender, std::uint64_t stream_ordering,
                    std::string const& status = "accepted") -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = sender;
    event.json = R"({"type":"m.room.message","content":{"body":"x"}})";
    event.stream_ordering = stream_ordering;
    event.status = status;
    store.events.push_back(std::move(event));
}

} // namespace

// ADR-0435: a room's unread state is read from that room's rows alone, whatever else the store holds.
SCENARIO("Unread counts and read markers read only the room they are asked about", "[sync][read-markers][room-stream]")
{
    GIVEN("two rooms, a backfilled event ordered late, an outlier, a rejected event and a foreign receipt")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const room = std::string{"!room:example.org"};
        auto const other = std::string{"!other:example.org"};
        add_room_event(store, "$a1", room, "@bob:example.org", 10U);
        add_room_event(store, "$b1", other, "@bob:example.org", 11U);
        add_room_event(store, "$a2", room, "@bob:example.org", 20U);
        add_room_event(store, "$b2", other, "@bob:example.org", 21U);
        add_room_event(store, "$a-mine", room, "@alice:example.org", 25U);
        add_room_event(store, "$a-rejected", room, "@bob:example.org", 26U, "rejected");
        add_room_event(store, "$a-outlier", room, "@bob:example.org", 27U, "outlier");
        add_room_event(store, "$a-backfilled", room, "@bob:example.org", 40U);
        // Committed out of order: after newer rows were stored.
        add_room_event(store, "$a-late", room, "@bob:example.org", 15U);
        auto receipts = std::vector<merovingian::database::PersistentReceipt>{
            {room, "m.read", "@alice:example.org", "$a1", 0U, 1U, {}       },
            // Names an event of another room: it marks nothing here.
            {room, "m.read", "@alice:example.org", "$b2", 0U, 2U, "$thread"},
        };

        WHEN("alice's markers and unread counts in the room are built")
        {
            auto const markers = merovingian::sync::read_markers_for(receipts, store, room, "@alice:example.org");
            auto classifier = RecordingClassifier{};
            auto const counts =
                merovingian::sync::count_unread_by_thread(store, room, "@alice:example.org", markers, classifier);

            THEN("the receipt for another room's event moves nothing and her own event reads its thread")
            {
                REQUIRE(markers.threads.find("$thread") == markers.threads.end());
                REQUIRE(markers.unthreaded == 10U);
                REQUIRE(markers.threads.at("main") == 25U);
            }
            THEN("only accepted events of the room above the markers are counted, backfilled ones included")
            {
                // $a2 (20) and $a-late (15) lie under her own event's main-thread position (25);
                // $a-backfilled (40) does not.
                REQUIRE(counts.total().notification_count == 1U);
            }
            THEN("no event of the other room, and no rejected or outlier event, was judged")
            {
                REQUIRE(classifier.asked.contains("$a-backfilled"));
                REQUIRE_FALSE(classifier.asked.contains("$b1"));
                REQUIRE_FALSE(classifier.asked.contains("$b2"));
                REQUIRE_FALSE(classifier.asked.contains("$a-rejected"));
                REQUIRE_FALSE(classifier.asked.contains("$a-outlier"));
            }
        }
    }
}
