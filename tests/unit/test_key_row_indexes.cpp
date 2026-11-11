// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit release gate (ADR-0603, ADR-0606). The user, device, device-key, one-time-key, fallback-key,
// membership and key-backup tables are vectors the federation key and EDU paths and the key backup routes looked
// through with a scan per key under the runtime lock. Each now has an index beside it that is trusted only while it
// is in step with its vector. These scenarios prove the work of a lookup is the rows it names, not the table, that
// every writer keeps the index right, and that a rebuilt index (as after a reload from the database) answers the
// same. Cost is shown with the stores' rows-examined counters, never with time.

#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto open_store() -> db::PersistentStore
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    return std::move(opened.store);
}

// A store holding `other_devices` devices of other users, each with a device key, a one-time key and a fallback key,
// so a lookup that scanned would read them all.
[[nodiscard]] auto store_with_other_devices(std::size_t other_devices) -> db::PersistentStore
{
    auto store = open_store();
    for (auto index = std::size_t{0U}; index < other_devices; ++index)
    {
        auto const user = "@other" + std::to_string(index) + ":example.org";
        REQUIRE(db::store_device(store, {user, "DEV", "name"}));
        REQUIRE(db::store_device_key(store, {user, "DEV", R"({"keys":{}})"}));
        REQUIRE(db::store_one_time_key(store, {user, "DEV", "signed_curve25519:K", R"({"key":"k"})"}));
        REQUIRE(db::store_fallback_key(store, {user, "DEV", "signed_curve25519:F", R"({"key":"f"})"}));
    }
    return store;
}

constexpr auto alice = "@alice:example.org";

} // namespace

SCENARIO("a one-time key claim reads only the claiming device's rows, whatever else the server holds",
         "[keys][index][one-time-keys][adr-0603]")
{
    GIVEN("two stores, with 20 and with 2000 other devices' keys, and alice holding three one-time keys")
    {
        auto small = store_with_other_devices(20U);
        auto large = store_with_other_devices(2000U);
        for (auto* store : {&small, &large})
        {
            for (auto const* id : {"signed_curve25519:A", "signed_curve25519:B", "signed_curve25519:C"})
            {
                REQUIRE(db::store_one_time_key(*store, {alice, "DEV1", id, R"({"key":"x"})"}));
            }
        }

        WHEN("a key is claimed from alice's device in each store")
        {
            auto const small_before = small.key_rows_examined.value();
            auto const small_claim = db::claim_one_time_key(small, alice, "DEV1", "signed_curve25519");
            auto const small_rows = small.key_rows_examined.value() - small_before;
            auto const large_before = large.key_rows_examined.value();
            auto const large_claim = db::claim_one_time_key(large, alice, "DEV1", "signed_curve25519");
            auto const large_rows = large.key_rows_examined.value() - large_before;

            THEN("each claim reads the same few rows and returns one of alice's keys")
            {
                REQUIRE(small_claim.has_value());
                REQUIRE(large_claim.has_value());
                REQUIRE(small_rows == large_rows);
                REQUIRE(large_rows <= 3U);
                REQUIRE(large_claim->user_id == alice);
            }
        }

        WHEN("all of alice's keys are claimed, then one more")
        {
            auto claimed = std::set<std::string>{};
            for (auto round = 0; round < 3; ++round)
            {
                auto const key = db::claim_one_time_key(large, alice, "DEV1", "signed_curve25519");
                REQUIRE(key.has_value());
                claimed.insert(key->key_id);
            }
            auto const exhausted = db::claim_one_time_key(large, alice, "DEV1", "signed_curve25519");

            THEN("each key is handed out once, then none, and every other device still has its key")
            {
                REQUIRE(claimed.size() == 3U);
                REQUIRE_FALSE(exhausted.has_value());
                REQUIRE(large.one_time_keys.size() == 2000U);
                REQUIRE(
                    db::claim_one_time_key(large, "@other1999:example.org", "DEV", "signed_curve25519").has_value());
                REQUIRE(db::claim_one_time_key(large, "@other0:example.org", "DEV", "signed_curve25519").has_value());
            }
        }

        WHEN("keys are claimed so the last row moves into the gaps, and the index is then rebuilt as after a reload")
        {
            REQUIRE(db::claim_one_time_key(large, "@other3:example.org", "DEV", "signed_curve25519").has_value());
            REQUIRE(db::claim_one_time_key(large, "@other1:example.org", "DEV", "signed_curve25519").has_value());
            auto const before_rebuild = large.key_rows_examined.value();
            auto const live = db::claim_one_time_key(large, "@other1999:example.org", "DEV", "signed_curve25519");
            auto const live_rows = large.key_rows_examined.value() - before_rebuild;
            db::rebuild_key_indexes(large);
            auto const rebuilt = db::claim_one_time_key(large, alice, "DEV1", "signed_curve25519");

            THEN("a row moved by an earlier claim is still found at its new place, and a rebuilt index agrees")
            {
                REQUIRE(live.has_value());
                REQUIRE(live_rows == 1U);
                REQUIRE(rebuilt.has_value());
                REQUIRE(rebuilt->user_id == alice);
                REQUIRE_FALSE(
                    db::claim_one_time_key(large, "@other3:example.org", "DEV", "signed_curve25519").has_value());
                REQUIRE(large.one_time_keys.size() == 1999U);
            }
        }
    }
}

SCENARIO("a store whose vectors were edited directly falls back to a scan and answers correctly",
         "[keys][index][fallback-keys][adr-0603]")
{
    GIVEN("a store whose fallback keys were pushed straight into the vector")
    {
        auto store = open_store();
        for (auto index = 0; index < 50; ++index)
        {
            store.fallback_keys.push_back(
                {"@u" + std::to_string(index) + ":example.org", "DEV", "signed_curve25519:F", R"({"key":"f"})"});
        }

        WHEN("a key is looked up")
        {
            auto const before = store.key_rows_examined.value();
            auto const found = db::find_fallback_key(store, "@u49:example.org", "DEV", "signed_curve25519");
            auto const rows = store.key_rows_examined.value() - before;

            THEN("it is found by scanning the whole vector, which is the cost the index removes")
            {
                REQUIRE(found.has_value());
                REQUIRE(rows >= 50U);
            }
        }

        WHEN("a writer runs, it brings the index back in step")
        {
            REQUIRE(db::store_fallback_key(store, {"@new:example.org", "DEV", "signed_curve25519:N", R"({"key":"n"})"}));
            auto const before = store.key_rows_examined.value();
            auto const found = db::find_fallback_key(store, "@u10:example.org", "DEV", "signed_curve25519");
            auto const rows = store.key_rows_examined.value() - before;

            THEN("the next lookup reads one row")
            {
                REQUIRE(found.has_value());
                REQUIRE(rows == 1U);
            }
        }
    }
}

SCENARIO("fallback keys, device keys and devices are found and removed through their indexes",
         "[keys][index][device][adr-0603]")
{
    GIVEN("alice with two devices, each with keys, among 500 other devices")
    {
        auto store = store_with_other_devices(500U);
        for (auto const* device : {"DEV1", "DEV2"})
        {
            REQUIRE(db::store_device(store, {alice, device, "alice device"}));
            REQUIRE(db::store_device_key(store, {alice, device, R"({"keys":{}})"}));
            REQUIRE(db::store_one_time_key(store, {alice, device, "signed_curve25519:K", R"({"key":"k"})"}));
            REQUIRE(db::store_fallback_key(store, {alice, device, "signed_curve25519:F1", R"({"key":"f1"})"}));
        }

        WHEN("a new fallback key replaces the old one of the same algorithm")
        {
            REQUIRE(db::store_fallback_key(store, {alice, "DEV1", "signed_curve25519:F2", R"({"key":"f2"})"}));
            auto const found = db::find_fallback_key(store, alice, "DEV1", "signed_curve25519");
            auto const other = db::find_fallback_key(store, alice, "DEV2", "signed_curve25519");

            THEN("only the new key is held for that device and the other device is untouched")
            {
                REQUIRE(found.has_value());
                REQUIRE(found->key_id == "signed_curve25519:F2");
                REQUIRE(other.has_value());
                REQUIRE(other->key_id == "signed_curve25519:F1");
                REQUIRE(store.fallback_keys.size() == 502U);
            }
        }

        WHEN("a device's keys are looked up")
        {
            auto const before = store.device_table_rows_examined.value();
            auto const key = db::find_device_key(store, alice, "DEV2");
            auto const rows = store.device_table_rows_examined.value() - before;

            THEN("only alice's device-key rows are read")
            {
                REQUIRE(key.has_value());
                REQUIRE(rows <= 2U);
            }
        }

        WHEN("one device is deleted")
        {
            REQUIRE(db::delete_device(store, alice, "DEV1"));

            THEN("its keys are gone, the other device's are not, and a rebuilt index agrees")
            {
                REQUIRE_FALSE(db::find_device_key(store, alice, "DEV1").has_value());
                REQUIRE(db::find_device_key(store, alice, "DEV2").has_value());
                REQUIRE_FALSE(db::find_fallback_key(store, alice, "DEV1").has_value());
                REQUIRE(db::find_fallback_key(store, alice, "DEV2").has_value());
                REQUIRE_FALSE(db::claim_one_time_key(store, alice, "DEV1").has_value());
                REQUIRE(store.one_time_keys.size() == 501U);
                REQUIRE(store.device_keys.size() == 501U);

                db::rebuild_key_indexes(store);
                REQUIRE_FALSE(db::find_device_key(store, alice, "DEV1").has_value());
                REQUIRE(db::find_device_key(store, alice, "DEV2").has_value());
                auto devices = std::vector<std::string>{};
                db::for_each_user_device(store, alice, [&](db::PersistentDevice const& device) {
                    devices.push_back(device.device_id);
                    return true;
                });
                REQUIRE(devices == std::vector<std::string>{"DEV2"});
            }
        }
    }
}

SCENARIO("users and memberships are found by key and the index follows every insert",
         "[keys][index][membership][adr-0603]")
{
    GIVEN("a store with 3000 users and 3000 membership rows")
    {
        auto store = open_store();
        for (auto index = 0; index < 3000; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":example.org";
            REQUIRE(db::store_user(store, {user, "hash", false, false, false}));
            store.memberships.push_back({"!room" + std::to_string(index % 100) + ":example.org", user, "join", 1U});
        }
        db::rebuild_membership_index(store);

        WHEN("a user, a membership and a room are looked up")
        {
            auto const users_before = store.user_rows_examined.value();
            auto const* const user = db::find_user_row(store, "@u2999:example.org");
            auto const* const ghost = db::find_user_row(store, "@ghost:example.org");
            auto const user_rows = store.user_rows_examined.value() - users_before;
            auto const members_before = store.membership_rows_examined.value();
            auto const* const member = db::find_membership_row(store, "!room99:example.org", "@u2999:example.org");
            auto const* const absent = db::find_membership_row(store, "!room1:example.org", "@u2999:example.org");
            auto const known_room = db::has_room_membership_row(store, "!room5:example.org");
            auto const unknown_room = db::has_room_membership_row(store, "!nowhere:example.org");
            auto const member_rows = store.membership_rows_examined.value() - members_before;

            THEN("each lookup reads one row and answers correctly")
            {
                REQUIRE(user != nullptr);
                REQUIRE(user->user_id == "@u2999:example.org");
                REQUIRE(ghost == nullptr);
                REQUIRE(user_rows == 2U);
                REQUIRE(member != nullptr);
                REQUIRE(member->membership == "join");
                REQUIRE(absent == nullptr);
                REQUIRE(known_room);
                REQUIRE_FALSE(unknown_room);
                REQUIRE(member_rows == 4U);
            }
        }

        WHEN("a membership is stored, and stored again")
        {
            auto const first = db::store_membership(store, {"!fresh:example.org", "@u1:example.org", "join", 5U});
            auto const second = db::store_membership(store, {"!fresh:example.org", "@u1:example.org", "join", 6U});
            auto const before = store.membership_rows_examined.value();
            auto const* const row = db::find_membership_row(store, "!fresh:example.org", "@u1:example.org");
            auto const rows = store.membership_rows_examined.value() - before;

            THEN("the new row is found with one row read and the repeat is not stored twice")
            {
                REQUIRE(first == db::MembershipStoreResult::stored);
                REQUIRE(second == db::MembershipStoreResult::already_exists);
                REQUIRE(row != nullptr);
                REQUIRE(rows == 1U);
                REQUIRE(std::ranges::count_if(store.memberships, [](db::PersistentMembership const& membership) {
                            return membership.room_id == "!fresh:example.org";
                        }) == 1);
            }
        }
    }
}

SCENARIO("key backup sessions are stored, counted, replaced and deleted through their indexes",
         "[keys][index][key-backup][adr-0606]")
{
    GIVEN("a store holding two backup versions for alice and one for bob")
    {
        auto store = open_store();
        REQUIRE(db::create_key_backup_version(store, alice, R"({"algorithm":"a"})") == "1");
        REQUIRE(db::create_key_backup_version(store, alice, R"({"algorithm":"a"})") == "2");
        REQUIRE(db::create_key_backup_version(store, "@bob:example.org", R"({"algorithm":"a"})") == "1");

        WHEN("a batch of 1000 sessions is stored in version 1")
        {
            auto batch = std::vector<db::PersistentKeyBackupSession>{};
            for (auto index = 0; index < 1000; ++index)
            {
                batch.push_back({alice, "1", "!room" + std::to_string(index % 10) + ":example.org",
                                 "session" + std::to_string(index), R"({"n":1})"});
            }
            auto const before = store.key_backup_rows_examined.value();
            REQUIRE(db::store_key_backup_sessions(store, std::move(batch)));
            auto const rows = store.key_backup_rows_examined.value() - before;

            THEN("the batch costs one lookup per session, not one pass of the table per session")
            {
                REQUIRE(rows == 1000U);
                REQUIRE(db::count_key_backup_sessions(store, alice, "1") == 1000U);
                REQUIRE(db::count_key_backup_sessions(store, alice, "2") == 0U);
                REQUIRE(db::count_user_key_backup_sessions(store, alice) == 1000U);
                REQUIRE(db::count_user_key_backup_sessions(store, "@bob:example.org") == 0U);
            }
        }

        WHEN("sessions are stored, one is replaced in place, and others are deleted singly, by room and by version")
        {
            for (auto index = 0; index < 30; ++index)
            {
                REQUIRE(db::store_key_backup_session(store, {alice, "1", "!room" + std::to_string(index % 3) + ":x",
                                                             "s" + std::to_string(index), R"({"n":1})"}));
            }
            REQUIRE(db::store_key_backup_session(store, {alice, "2", "!room0:x", "s0", R"({"n":2})"}));
            REQUIRE(db::store_key_backup_session(store, {"@bob:example.org", "1", "!room0:x", "s0", R"({"n":3})"}));
            REQUIRE(db::store_key_backup_session(store, {alice, "1", "!room0:x", "s0", R"({"n":4})"}));
            REQUIRE(db::delete_key_backup_session(store, alice, "1", "!room1:x", "s1"));
            REQUIRE(db::delete_key_backup_room_sessions(store, alice, "1", "!room2:x"));

            THEN("counts and finds are exact, other users and versions are untouched, and a rebuilt index agrees")
            {
                // room0 holds s0, s3 ... s27 (10), room1 s1, s4 ... s28 (10, minus s1), room2 is gone.
                REQUIRE(db::count_key_backup_sessions(store, alice, "1") == 19U);
                REQUIRE(db::find_key_backup_session(store, alice, "1", "!room0:x", "s0")->json == R"({"n":4})");
                REQUIRE(db::find_key_backup_session(store, alice, "1", "!room1:x", "s1") == nullptr);
                REQUIRE(db::find_key_backup_session(store, alice, "1", "!room2:x", "s2") == nullptr);
                REQUIRE(db::find_key_backup_session(store, alice, "1", "!room1:x", "s4") != nullptr);
                REQUIRE(db::find_key_backup_session(store, alice, "2", "!room0:x", "s0")->json == R"({"n":2})");
                REQUIRE(db::find_key_backup_session(store, "@bob:example.org", "1", "!room0:x", "s0")->json ==
                        R"({"n":3})");
                REQUIRE(store.key_backup_sessions.size() == 21U);

                db::rebuild_key_indexes(store);
                REQUIRE(db::count_key_backup_sessions(store, alice, "1") == 19U);
                REQUIRE(db::count_key_backup_sessions(store, alice, "2") == 1U);
                REQUIRE(db::find_key_backup_session(store, alice, "1", "!room1:x", "s4") != nullptr);

                REQUIRE(db::delete_key_backup_version(store, alice, "1"));
                REQUIRE(db::count_key_backup_sessions(store, alice, "1") == 0U);
                REQUIRE(db::count_key_backup_sessions(store, alice, "2") == 1U);
                REQUIRE(db::count_key_backup_versions(store, alice) == 1U);
                REQUIRE(db::latest_key_backup_version(store, alice)->version == "2");
                REQUIRE(db::find_key_backup_session(store, "@bob:example.org", "1", "!room0:x", "s0") != nullptr);
                REQUIRE(store.key_backup_sessions.size() == 2U);
            }
        }

        WHEN("sessions of a version are listed")
        {
            for (auto index = 0; index < 5; ++index)
            {
                REQUIRE(db::store_key_backup_session(store, {alice, "1", "!r:x", "s" + std::to_string(index), "{}"}));
                REQUIRE(db::store_key_backup_session(store, {alice, "2", "!r:x", "t" + std::to_string(index), "{}"}));
            }
            auto listed = std::set<std::string>{};
            db::for_each_key_backup_session(store, alice, "1", [&](db::PersistentKeyBackupSession const& session) {
                listed.insert(session.session_id);
            });

            THEN("only that version's sessions are visited")
            {
                REQUIRE(listed == std::set<std::string>{"s0", "s1", "s2", "s3", "s4"});
            }
        }
    }
}
