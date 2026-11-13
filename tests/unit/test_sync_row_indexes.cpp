// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Run-3 finding C34, the per-request variants (ADR-0659): a sync reads the device-list changes of its own user, the
// filters of its own user, the presence rows of the users it can see and the rooms the push-rule classifier needs
// through standing indexes, never by walking a server-wide table. Cost is shown with the rows-examined counters.
//
// Spec: client-server-api.md, GET /sync (`device_lists`, `presence`), and "Filtering".

#include "../support/TempDirectory.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/PersistentDeviceListChange.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentFilter.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/PresenceService.hpp"
#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/push/PushRuleset.hpp"
#include "merovingian/sync/DeviceListDelta.hpp"
#include "merovingian/sync/SyncFilter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-sync-indexes-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto observer(std::size_t index) -> std::string
{
    return "@observer" + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto change(std::string observer_id, std::string subject, std::string type = "changed")
    -> db::PersistentDeviceListChange
{
    auto row = db::PersistentDeviceListChange{};
    row.observer_user_id = std::move(observer_id);
    row.subject_user_id = std::move(subject);
    row.change_type = std::move(type);
    return row;
}

[[nodiscard]] auto rows_of(db::PersistentStore const& store, std::string const& who)
    -> std::vector<db::PersistentDeviceListChange>
{
    auto rows = std::vector<db::PersistentDeviceListChange>{};
    db::for_each_observer_device_list_change(store, who, [&](db::PersistentDeviceListChange const& row) {
        rows.push_back(row);
    });
    return rows;
}

} // namespace

SCENARIO("device-list changes are read and replaced through the observer index", "[sync][c34][index][device-lists]")
{
    GIVEN("two hundred observers, each holding changes about three subjects")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto index = std::size_t{0U}; index < 200U; ++index)
        {
            auto batch = std::vector<db::PersistentDeviceListChange>{};
            for (auto subject = 0; subject < 3; ++subject)
            {
                batch.push_back(change(observer(index), "@subject" + std::to_string(subject) + ":example.org"));
            }
            REQUIRE(db::record_device_list_changes(store, std::move(batch)));
        }
        REQUIRE(store.device_list_changes.size() == 600U);

        WHEN("one observer's changes are read")
        {
            auto const before = store.device_list_rows_examined.value();
            auto const rows = rows_of(store, observer(42U));

            THEN("exactly its three rows are returned and examined")
            {
                REQUIRE(rows.size() == 3U);
                REQUIRE(store.device_list_rows_examined.value() - before == 3U);
            }
        }

        WHEN("a pair's change is recorded again, as left")
        {
            auto const before = store.device_list_rows_examined.value();
            REQUIRE(db::record_device_list_change(store, change(observer(7U), "@subject1:example.org", "left")));

            THEN("the observer still holds one row per subject, the old row replaced, and the table was not scanned")
            {
                REQUIRE(store.device_list_changes.size() == 600U);
                REQUIRE(store.device_list_observer_index.in_step(store.device_list_changes.size()));
                auto const rows = rows_of(store, observer(7U));
                REQUIRE(rows.size() == 3U);
                auto lefts = 0;
                for (auto const& row : rows)
                {
                    lefts += row.change_type == "left" ? 1 : 0;
                }
                REQUIRE(lefts == 1);
                REQUIRE(store.device_list_rows_examined.value() - before <= 6U);
                REQUIRE(rows_of(store, observer(8U)).size() == 3U);
            }

            THEN("the delta the sync builds from the rows is right, and reads only the observer's rows")
            {
                auto const examined = store.device_list_rows_examined.value();
                auto const delta = merovingian::sync::collect_device_list_delta(store, observer(7U), 0U, 1000000U);
                REQUIRE(delta.left == std::vector<std::string>{"@subject1:example.org"});
                REQUIRE(delta.changed.size() == 2U);
                REQUIRE(store.device_list_rows_examined.value() - examined == 3U);
            }
        }
    }
}

SCENARIO("the device-list index is rebuilt when the store is loaded again", "[sync][c34][index][device-lists]")
{
    GIVEN("a database whose pairs were replaced after they were first written")
    {
        auto const path = unique_sqlite_path();
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            for (auto index = std::size_t{0U}; index < 5U; ++index)
            {
                REQUIRE(db::record_device_list_change(opened.store, change(observer(index), "@s:example.org")));
            }
            REQUIRE(db::record_device_list_change(opened.store, change(observer(2U), "@s:example.org", "left")));
        }

        WHEN("it is opened again")
        {
            auto reloaded = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reloaded.ok);
            auto& store = reloaded.store;

            THEN("the index is in step and answers exactly the surviving rows")
            {
                REQUIRE(store.device_list_changes.size() == 5U);
                REQUIRE(store.device_list_observer_index.in_step(store.device_list_changes.size()));
                auto const before = store.device_list_rows_examined.value();
                auto const rows = rows_of(store, observer(2U));
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().change_type == "left");
                REQUIRE(store.device_list_rows_examined.value() - before == 1U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("stored filters are read through the user index", "[sync][c34][index][filters]")
{
    GIVEN("a hundred users, each storing three filters")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto user = std::size_t{0U}; user < 100U; ++user)
        {
            for (auto filter = 0; filter < 3; ++filter)
            {
                REQUIRE(db::store_filter(store, {"@u" + std::to_string(user) + ":example.org",
                                                 "f" + std::to_string(filter), R"({"room":{}})"}));
            }
        }

        WHEN("one user's filters are listed and one is looked up")
        {
            auto const before = store.filter_rows_examined.value();
            auto count = 0;
            db::for_each_user_filter(store, "@u9:example.org", [&](db::PersistentFilter const&) {
                ++count;
            });
            auto const listed = store.filter_rows_examined.value() - before;
            auto const found = db::find_filter(store, "@u9:example.org", "f1");

            THEN("only that user's rows are read")
            {
                REQUIRE(count == 3);
                REQUIRE(listed == 3U);
                REQUIRE(found.has_value());
                REQUIRE(store.filter_rows_examined.value() - before <= 6U);
                REQUIRE_FALSE(db::find_filter(store, "@u9:example.org", "missing").has_value());
            }
        }

        WHEN("a stored filter is replaced")
        {
            REQUIRE(db::store_filter(store, {"@u9:example.org", "f1", R"({"room":{"include_leave":true}})"}));

            THEN("the user still holds three filters and the new text")
            {
                REQUIRE(store.filters.size() == 300U);
                REQUIRE(store.filter_user_index.in_step(store.filters.size()));
                REQUIRE(db::find_filter(store, "@u9:example.org", "f1")->json == R"({"room":{"include_leave":true}})");
            }
        }
    }

    GIVEN("a database of filters")
    {
        auto const path = unique_sqlite_path();
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_filter(opened.store, {"@a:example.org", "one", R"({"a":1})"}));
            REQUIRE(db::store_filter(opened.store, {"@b:example.org", "one", R"({"b":1})"}));
            REQUIRE(db::store_filter(opened.store, {"@a:example.org", "one", R"({"a":2})"}));
        }

        WHEN("it is opened again")
        {
            auto reloaded = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reloaded.ok);

            THEN("the index is in step and the replaced text is the one found")
            {
                REQUIRE(reloaded.store.filter_user_index.in_step(reloaded.store.filters.size()));
                REQUIRE(db::find_filter(reloaded.store, "@a:example.org", "one")->json == R"({"a":2})");
                REQUIRE(db::find_filter(reloaded.store, "@b:example.org", "one")->json == R"({"b":1})");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("presence rows are found through the user index", "[sync][c34][index][presence]")
{
    GIVEN("presence rows for five hundred users")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto user = std::size_t{0U}; user < 500U; ++user)
        {
            auto row = db::PersistentPresence{};
            row.user_id = "@p" + std::to_string(user) + ":example.org";
            row.presence = "online";
            REQUIRE(db::upsert_presence(store, row));
        }

        WHEN("one user's row is looked up, and another user's is replaced")
        {
            auto const before = store.presence_rows_examined.value();
            auto const* found = db::find_presence_state(store, "@p123:example.org");
            auto const examined = store.presence_rows_examined.value() - before;
            auto replacement = db::PersistentPresence{};
            replacement.user_id = "@p7:example.org";
            replacement.presence = "offline";
            REQUIRE(db::upsert_presence(store, replacement));

            THEN("one row is read for the lookup, the replacement adds no row, and a stranger has none")
            {
                REQUIRE(found != nullptr);
                REQUIRE(found->user_id == "@p123:example.org");
                REQUIRE(examined == 1U);
                REQUIRE(store.presence_states.size() == 500U);
                REQUIRE(db::find_presence_state(store, "@p7:example.org")->presence == "offline");
                REQUIRE(db::find_presence_state(store, "@nobody:example.org") == nullptr);
            }
        }
    }

    GIVEN("a database of presence rows")
    {
        auto const path = unique_sqlite_path();
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            for (auto const* user : {"@a:example.org", "@b:example.org"})
            {
                auto row = db::PersistentPresence{};
                row.user_id = user;
                row.presence = "online";
                REQUIRE(db::upsert_presence(opened.store, row));
            }
        }

        WHEN("it is opened again")
        {
            auto reloaded = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reloaded.ok);

            THEN("the index is in step and finds both rows")
            {
                REQUIRE(reloaded.store.presence_user_index.in_step(reloaded.store.presence_states.size()));
                REQUIRE(db::find_presence_state(reloaded.store, "@a:example.org") != nullptr);
                REQUIRE(db::find_presence_state(reloaded.store, "@b:example.org") != nullptr);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("the push-rule classifier reads the user's rooms and no server-wide table", "[sync][c34][index][push]")
{
    GIVEN("two rooms of the user among fifteen hundred rooms of other users")
    {
        auto store = db::PersistentStore{};
        auto const alice = std::string{"@alice:example.org"};
        auto const add_state = [&](std::string const& room, std::string const& event_id, std::string const& type,
                                   std::string const& state_key, std::string const& content) {
            auto event = db::PersistentEvent{};
            event.event_id = event_id;
            event.room_id = room;
            event.sender_user_id = "@bob:example.org";
            event.json = R"({"type":")" + type + R"(","state_key":")" + state_key + R"(","content":)" + content + "}";
            event.stream_ordering = 1U;
            store.events.push_back(std::move(event));
            store.state.push_back({room, type, state_key, event_id});
        };
        for (auto const* room : {"!mine1:x", "!mine2:x"})
        {
            store.memberships.push_back({room, alice, "join", 1U});
            store.memberships.push_back({room, "@bob:example.org", "join", 1U});
            add_state(room, std::string{"$pl-"} + room, "m.room.power_levels", "", R"({"users_default":0})");
            add_state(room, std::string{"$create-"} + room, "m.room.create", "", R"({"room_version":"10"})");
        }
        for (auto index = std::size_t{0U}; index < 1500U; ++index)
        {
            auto const room = "!other" + std::to_string(index) + ":x";
            store.memberships.push_back({room, "@carol:example.org", "join", 1U});
            add_state(room, "$other" + std::to_string(index), "m.room.power_levels", "", "{}");
        }
        db::rebuild_key_indexes(store);
        db::rebuild_membership_index(store);
        db::rebuild_state_index(store);

        WHEN("a message is classified in one of the user's rooms")
        {
            auto const members_before = store.membership_rows_examined.value();
            auto const state_before = store.state_rows_examined.value();
            auto const parsed = merovingian::canonicaljson::parse_lossless(
                R"({"type":"m.room.message","sender":"@bob:example.org","content":{"msgtype":"m.text","body":"hi"}})");
            auto classifier = merovingian::homeserver::PushRuleUnreadClassifier{store, alice, 200U};
            std::ignore = classifier.classify("!mine1:x", parsed.value);

            THEN("only the user's rows and the user's rooms' rows were read")
            {
                // Compared directly, not by difference: the counters are unsigned, so `after - before > 0` is
                // only `after != before`. The rise is proved first, so the subtraction below cannot wrap.
                REQUIRE(store.membership_rows_examined.value() >= members_before);
                REQUIRE(store.state_rows_examined.value() > state_before);
                REQUIRE(store.membership_rows_examined.value() - members_before <= 12U);
                REQUIRE(store.state_rows_examined.value() - state_before <= 12U);
            }
        }
    }
}

SCENARIO("a sync reads the presence of the users it can see, not the presence table", "[sync][c34][index][presence]")
{
    GIVEN("alice and bob in one room, carol in another, and presence rows for five hundred other users")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        store.memberships.push_back({"!shared:x", "@alice:example.org", "join", 1U});
        store.memberships.push_back({"!shared:x", "@bob:example.org", "join", 1U});
        store.memberships.push_back({"!apart:x", "@carol:example.org", "join", 1U});
        db::rebuild_key_indexes(store);
        db::rebuild_membership_index(store);
        for (auto const* user : {"@bob:example.org", "@carol:example.org"})
        {
            auto row = db::PersistentPresence{};
            row.user_id = user;
            row.presence = "online";
            REQUIRE(db::upsert_presence(store, row));
        }
        for (auto index = std::size_t{0U}; index < 500U; ++index)
        {
            auto row = db::PersistentPresence{};
            row.user_id = "@filler" + std::to_string(index) + ":example.org";
            row.presence = "online";
            REQUIRE(db::upsert_presence(store, row));
        }

        WHEN("alice's initial sync builds her presence events")
        {
            auto const before = store.presence_rows_examined.value();
            auto max_observed = std::uint64_t{0U};
            auto const events = merovingian::homeserver::build_sync_presence_events(
                store, merovingian::sync::EventTypeFilter{}, "@alice:example.org", false, 0U, 0U, 1000U, 0,
                max_observed);

            THEN("only bob's presence is sent, and one presence row was read for each user she shares a room with")
            {
                REQUIRE(events.size() == 1U);
                REQUIRE(store.presence_rows_examined.value() > before);
                REQUIRE(store.presence_rows_examined.value() - before <= 3U);
            }
        }
    }
}
