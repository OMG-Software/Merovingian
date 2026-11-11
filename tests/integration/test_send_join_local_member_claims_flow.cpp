// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0630. A resident's send_join snapshot is a claim about the room. For a user of this server it is taken only when
// this server holds no row for the user in the room, or the claimed event is the one held as current; otherwise this
// server's own record stands. The snapshot's state group is built from what the ingest returns, so a refused claim must
// not be in it either, or a later recompute_current_state (ADR-0615) would bring it back.
#include "../support/Genesis.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MembershipAcceptorFixture.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;
using tests::membership_acceptor_fixture::build_event_json;
using tests::membership_acceptor_fixture::config_with_sqlite;
using tests::membership_acceptor_fixture::seed_room_genesis;
using tests::membership_acceptor_fixture::unique_sqlite_path;

auto const admin = std::string{"@admin:local.example.org"};
auto const zed = std::string{"@zed:local.example.org"};
auto const newbie = std::string{"@newbie:local.example.org"};
auto const carol = std::string{"@carol:remote.example.org"};
auto const joiner = std::string{"@joiner:local.example.org"};

[[nodiscard]] auto member_content(std::string const& membership) -> canonicaljson::Object
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{membership}));
    return content;
}

[[nodiscard]] auto membership_of(database::PersistentStore const& store, std::string const& room_id,
                                 std::string const& user) -> std::string
{
    auto const row = std::ranges::find_if(store.memberships, [&](database::PersistentMembership const& candidate) {
        return candidate.room_id == room_id && candidate.user_id == user;
    });
    return row == store.memberships.end() ? std::string{} : row->membership;
}

// Records a member event as already accepted: its state group, and current state by recomputation, as ingestion would.
// (The shared fixture's seed also writes a state row of its own, which would leave two rows for one key.)
auto seed_member(homeserver::HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id,
                 std::string const& user, std::string const& sender, std::string const& membership,
                 std::vector<std::string> const& prev, std::vector<std::string> const& auth, std::int64_t depth) -> void
{
    auto const* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;
    auto const unsigned_depth = static_cast<std::uint64_t>(depth);
    store.events.push_back({event_id,
                            room_id,
                            sender,
                            build_event_json(room_id, "m.room.member", user, sender, member_content(membership), prev,
                                             auth, depth, depth + 1),
                            unsigned_depth,
                            unsigned_depth + 1U,
                            prev,
                            auth,
                            {}});
    auto const before = homeserver::compute_state_before(store, room_id, *policy, prev);
    REQUIRE(before.ok);
    auto const after = homeserver::compute_state_after(before.state, event_id, "m.room.member", user);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev, after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    auto const row = std::ranges::find_if(store.memberships, [&](database::PersistentMembership const& candidate) {
        return candidate.room_id == room_id && candidate.user_id == user;
    });
    if (row == store.memberships.end())
    {
        store.memberships.push_back({room_id, user, membership, unsigned_depth + 1U});
    }
    else
    {
        row->membership = membership;
    }
}

[[nodiscard]] auto parsed_array(std::vector<std::string> const& json_events) -> canonicaljson::Array
{
    auto array = canonicaljson::Array{};
    for (auto const& json : json_events)
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        array.push_back(parsed.value);
    }
    return array;
}

[[nodiscard]] auto event_id_of(std::string const& json, rooms::RoomVersionPolicy const& policy) -> std::string
{
    auto const parsed = canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto const id = events::make_reference_hash_event_id(parsed.value, policy);
    REQUIRE_FALSE(id.event_id.empty());
    return id.event_id;
}

} // namespace

SCENARIO("A resident's send_join snapshot does not move a local user's membership",
         "[gate-l][send_join][membership][state_group]")
{
    GIVEN("a room in which this server banned zed, and a snapshot that claims zed's old join, carol's join and a "
          "join of a local user this server holds nothing for")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const room_id = std::string{"!snap:local.example.org"};
        {
            auto started = homeserver::start_runtime(config_with_sqlite(path));
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto& store = runtime.database.persistent_store;
            auto const* policy = rooms::find_room_version_policy("10");
            REQUIRE(policy != nullptr);
            auto const genesis = seed_room_genesis(runtime, room_id, admin);
            auto const auth = std::vector<std::string>{genesis.create_id, genesis.pl_id, genesis.join_rules_id};

            auto const zed_join_id = room_id + ":zed-join";
            seed_member(runtime, room_id, zed_join_id, zed, zed, "join", {genesis.join_rules_id}, auth, 4);
            auto const zed_ban_id = room_id + ":zed-ban";
            seed_member(runtime, room_id, zed_ban_id, zed, admin, "ban", {zed_join_id}, auth, 5);
            database::rebuild_membership_index(store);
            REQUIRE(database::find_current_state_event_id(store, room_id, "m.room.member", zed) == zed_ban_id);
            REQUIRE(membership_of(store, room_id, zed) == "ban");

            auto stale_content = member_content("join");
            stale_content.push_back(
                canonicaljson::make_member("displayname", canonicaljson::Value{std::string{"old"}}));
            auto const stale_json = build_event_json(room_id, "m.room.member", zed, zed, std::move(stale_content),
                                                     {genesis.create_id}, {genesis.create_id}, 3, 7);
            auto const stale_id = event_id_of(stale_json, *policy);
            auto const carol_json = build_event_json(room_id, "m.room.member", carol, carol, member_content("join"),
                                                     {genesis.create_id}, {genesis.create_id}, 3, 8);
            auto const newbie_json = build_event_json(room_id, "m.room.member", newbie, newbie, member_content("join"),
                                                      {genesis.create_id}, {genesis.create_id}, 3, 9);
            auto const snapshot = parsed_array({stale_json, carol_json, newbie_json});

            WHEN("the snapshot is ingested and a join is then recorded on the state it built")
            {
                auto const ingested = homeserver::ingest_send_join_state(runtime, room_id, snapshot, *policy);
                auto const entry_for = [&](std::string const& user) {
                    return std::ranges::find_if(ingested.state_entries, [&](auto const& entry) {
                        return entry.event_type == "m.room.member" && entry.state_key == user;
                    });
                };

                auto const join_id = room_id + ":joiner-join";
                auto const join_json = build_event_json(room_id, "m.room.member", joiner, joiner,
                                                        member_content("join"), {genesis.create_id}, auth, 6, 10);
                store.events.push_back({join_id, room_id, joiner, join_json, 6U, 0U, {}, {}, {}});
                auto const after =
                    homeserver::compute_state_after(ingested.state_entries, join_id, "m.room.member", joiner);
                REQUIRE(homeserver::record_event_state(store, room_id, join_id,
                                                       database::find_forward_extremities(store, room_id), after, true)
                            .has_value());
                REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));

                THEN("zed stays banned: the row, current state and the state group keep this server's own event")
                {
                    REQUIRE(membership_of(store, room_id, zed) == "ban");
                    REQUIRE(database::find_current_state_event_id(store, room_id, "m.room.member", zed) == zed_ban_id);
                    REQUIRE(entry_for(zed) != ingested.state_entries.end());
                    REQUIRE(entry_for(zed)->event_id == zed_ban_id);
                    REQUIRE(std::ranges::none_of(ingested.state_entries, [&](auto const& entry) {
                        return entry.event_id == stale_id;
                    }));
                    REQUIRE(std::ranges::find(ingested.joined_members, zed) == ingested.joined_members.end());
                }
                AND_THEN("the claims for a remote user and for a local user with no row are taken")
                {
                    REQUIRE(std::ranges::find(ingested.joined_members, carol) != ingested.joined_members.end());
                    REQUIRE(std::ranges::find(ingested.joined_members, newbie) != ingested.joined_members.end());
                    REQUIRE(database::find_current_state_event_id(store, room_id, "m.room.member", carol).has_value());
                    REQUIRE(database::find_current_state_event_id(store, room_id, "m.room.member", newbie).has_value());
                }
                AND_THEN("the joiner's own join landed")
                {
                    REQUIRE(database::find_current_state_event_id(store, room_id, "m.room.member", joiner) == join_id);
                }
            }
        }
        std::filesystem::remove(path);
    }
}
