// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0615. Spec: docs/matrix-v1.19-spec/server-server-api.md, "Room State Resolution": current state is the resolved
// state. A key only a losing fork set leaves it, durably, and the room's roster follows.

#include "../support/Genesis.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MembershipAcceptorFixture.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;
using federation::PduIngestionStatus;
using homeserver::HomeserverRuntime;
using tests::membership_acceptor_fixture::build_event_json;
using tests::membership_acceptor_fixture::config_with_sqlite;
using tests::membership_acceptor_fixture::make_envelope;
using tests::membership_acceptor_fixture::unique_sqlite_path;

auto const admin = std::string{"@admin:local.example.org"};
auto const moderator = std::string{"@mod:remote.example.org"};
auto const carol = std::string{"@carol:remote.example.org"};

[[nodiscard]] auto member_content(std::string const& membership) -> canonicaljson::Object
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{membership}));
    return content;
}

struct Room final
{
    std::string id{};
    std::string create{};
    std::string power_levels{};
    std::string join_rules{};
    std::string moderator_join{};
};

// Records an event as already accepted, with its auth_events, as ingestion would.
auto seed(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id, std::string const& type,
          std::string const& state_key, std::string const& sender, canonicaljson::Object content,
          std::vector<std::string> const& prev, std::vector<std::string> const& auth, std::int64_t depth) -> void
{
    auto* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;
    auto const unsigned_depth = static_cast<std::uint64_t>(depth);
    auto const json =
        build_event_json(room_id, type, state_key, sender, std::move(content), prev, auth, depth, depth + 1);
    store.events.push_back({event_id, room_id, sender, json, unsigned_depth, unsigned_depth + 1U, prev, auth, {}});
    auto const before = homeserver::compute_state_before(store, room_id, *policy, prev);
    REQUIRE(before.ok);
    auto const after = homeserver::compute_state_after(before.state, event_id, type, state_key);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev, after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
}

// A public room with a joined local admin and a joined remote moderator at power 100.
[[nodiscard]] auto seed_room(HomeserverRuntime& runtime, std::string const& room_id) -> Room
{
    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, admin});
    runtime.database.rooms.push_back({room_id, admin, {}, false});

    auto const create_id = room_id + ":create";
    auto create = canonicaljson::Object{};
    create.push_back(canonicaljson::make_member("creator", canonicaljson::Value{admin}));
    create.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
    seed(runtime, room_id, create_id, "m.room.create", std::string{}, admin, std::move(create), {}, {}, 0);

    auto const admin_join = room_id + ":admin";
    seed(runtime, room_id, admin_join, "m.room.member", admin, admin, member_content("join"), {create_id}, {create_id},
         1);

    auto const pl_id = room_id + ":pl";
    auto power = canonicaljson::Object{};
    power.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    auto users = canonicaljson::Object{};
    users.push_back(canonicaljson::make_member(admin, canonicaljson::Value{std::int64_t{100}}));
    users.push_back(canonicaljson::make_member(moderator, canonicaljson::Value{std::int64_t{100}}));
    power.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(users)}));
    seed(runtime, room_id, pl_id, "m.room.power_levels", std::string{}, admin, std::move(power), {admin_join},
         {create_id, admin_join}, 2);

    auto const rules_id = room_id + ":rules";
    auto rules = canonicaljson::Object{};
    rules.push_back(canonicaljson::make_member("join_rule", canonicaljson::Value{std::string{"public"}}));
    seed(runtime, room_id, rules_id, "m.room.join_rules", std::string{}, admin, std::move(rules), {pl_id},
         {create_id, pl_id, admin_join}, 3);

    auto const moderator_join = room_id + ":mod";
    seed(runtime, room_id, moderator_join, "m.room.member", moderator, moderator, member_content("join"), {rules_id},
         {create_id, pl_id, rules_id}, 4);
    store.memberships.push_back({room_id, admin, "join", 2U});
    store.memberships.push_back({room_id, moderator, "join", 5U});
    database::rebuild_membership_index(store);
    std::ignore = runtime.database.rooms.back().members.add(admin);
    std::ignore = runtime.database.rooms.back().members.add(moderator);
    return {room_id, create_id, pl_id, rules_id, moderator_join};
}

[[nodiscard]] auto ingest_carol_then_invite_only_fork(HomeserverRuntime& runtime, Room const& room) -> std::string
{
    auto const carol_join = std::string{"$carol-join:remote.example.org"};
    auto const auth = std::vector<std::string>{room.create, room.power_levels, room.join_rules};
    auto const join_json = build_event_json(room.id, "m.room.member", carol, carol, member_content("join"),
                                            {room.moderator_join}, auth, 5, 6);
    auto join_envelope =
        make_envelope(room.id, carol_join, "m.room.member", carol, carol, {room.moderator_join}, auth, 5, join_json);
    join_envelope.origin = "remote.example.org";
    REQUIRE(homeserver::ingest_pdu_event(runtime, join_envelope).status == PduIngestionStatus::accepted);
    REQUIRE(database::find_current_state_event_id(runtime.database.persistent_store, room.id, "m.room.member", carol) ==
            carol_join);

    auto rules = canonicaljson::Object{};
    rules.push_back(canonicaljson::make_member("join_rule", canonicaljson::Value{std::string{"invite"}}));
    auto const rules_auth = std::vector<std::string>{room.create, room.power_levels, room.moderator_join};
    auto const rules_json = build_event_json(room.id, "m.room.join_rules", std::string{}, moderator, std::move(rules),
                                             {room.moderator_join}, rules_auth, 5, 7);
    auto rules_envelope = make_envelope(room.id, "$invite-only:remote.example.org", "m.room.join_rules", std::string{},
                                        moderator, {room.moderator_join}, rules_auth, 5, rules_json);
    rules_envelope.origin = "remote.example.org";
    REQUIRE(homeserver::ingest_pdu_event(runtime, rules_envelope).status == PduIngestionStatus::accepted);
    return carol_join;
}

[[nodiscard]] auto membership_of(database::PersistentStore const& store, std::string const& room_id,
                                 std::string const& user) -> std::string
{
    auto const row = std::ranges::find_if(store.memberships, [&](database::PersistentMembership const& candidate) {
        return candidate.room_id == room_id && candidate.user_id == user;
    });
    return row == store.memberships.end() ? std::string{} : row->membership;
}

} // namespace

SCENARIO("A join only a losing fork made leaves current state, the row and the roster",
         "[gate-m][state_retraction][pdu_ingestion]")
{
    GIVEN("a public room in which carol joined on one fork")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const room_id = std::string{"!retract:local.example.org"};
        {
            auto started = homeserver::start_runtime(config_with_sqlite(path));
            REQUIRE(started.started);
            homeserver::wire_federation_callbacks(started.runtime);
            auto& runtime = started.runtime;
            auto const room = seed_room(runtime, room_id);

            WHEN("another fork makes the room invite-only")
            {
                std::ignore = ingest_carol_then_invite_only_fork(runtime, room);
                auto const& store = runtime.database.persistent_store;

                THEN("carol's key is gone, her row says leave and the roster no longer holds her")
                {
                    CHECK_FALSE(
                        database::find_current_state_event_id(store, room_id, "m.room.member", carol).has_value());
                    CHECK(membership_of(store, room_id, carol) == "leave");
                    auto const local = std::ranges::find_if(runtime.database.rooms, [&](auto const& candidate) {
                        return candidate.room_id == room_id;
                    });
                    REQUIRE(local != runtime.database.rooms.end());
                    CHECK_FALSE(local->members.contains(carol));
                    CHECK(local->members.contains(moderator));
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A removal from current state is written to the database", "[gate-m][state_retraction][database]")
{
    GIVEN("a SQLite-backed room in which a fork removed carol's key")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const room_id = std::string{"!retract-durable:local.example.org"};
        // Real rows are needed for a restart: drive the writes through the store's own API.
        auto opened = database::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto event = database::PersistentEvent{};
        event.event_id = "$durable";
        event.room_id = room_id;
        event.sender_user_id = carol;
        event.json = build_event_json(room_id, "m.room.member", carol, carol, member_content("join"), {}, {}, 1, 1);
        REQUIRE(database::store_user(store, {admin, "hash:retraction", false, false, false}));
        REQUIRE(database::store_room(store, {room_id, admin}));
        REQUIRE(database::store_event(store, event));
        REQUIRE(database::store_state(store, {room_id, "m.room.member", carol, "$durable"}));
        REQUIRE(database::store_membership_projection(store, room_id, {carol, "join", 3U, std::nullopt}));

        WHEN("the key is removed with its membership correction and the store is reopened")
        {
            auto const revision_before = database::room_state_revision(store, room_id);
            REQUIRE(database::remove_current_state_rows(store, room_id,
                                                        {
                                                            {"m.room.member", carol}
            },
                                                        {{carol, "leave", 9U, std::nullopt}}));
            auto reopened = database::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);

            THEN("the row is gone and the membership says leave")
            {
                CHECK_FALSE(
                    database::find_current_state_event_id(reopened.store, room_id, "m.room.member", carol).has_value());
                CHECK(membership_of(reopened.store, room_id, carol) == "leave");
            }

            // A cached send_join plan is stamped with this revision (ADR-0624), so a removal has to move it.
            THEN("the room's state revision has moved")
            {
                CHECK(database::room_state_revision(store, room_id) != revision_before);
            }
        }
        std::filesystem::remove(path);
    }
}
