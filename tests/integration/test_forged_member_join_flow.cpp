// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0612: the auth rules let any sender's join through while the only previous event is the create event and the
// state_key is the creator, because that rule sits before the check that the sender is the user joining. It is the
// consensus rule and is left alone, so a join naming another user is refused where a remote event is admitted.
//
// Spec: docs/matrix-v1.19-spec/rooms/v10.md, "Authorization rules", and docs/matrix-v1.19-spec/server-server-api.md,
// "Checks performed on receipt of a PDU" and "Rejection". Refusing the join at receipt is this server's choice.

#include "../support/Genesis.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MembershipAcceptorFixture.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/AuthorizedSendJoinAnswer.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/SendJoinAnswerAuthorization.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"
#include "merovingian/sync/HistoryVisibility.hpp"
#include "merovingian/sync/RoomReadAccess.hpp"
#include "merovingian/sync/RoomReadKind.hpp"

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

auto const local_admin = std::string{"@admin:local.example.org"};
auto const remote_creator = std::string{"@creator:remote.example.org"};
auto const mallory = std::string{"@mallory:evil.example"};

[[nodiscard]] auto with_membership(std::string const& membership) -> canonicaljson::Object
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{membership}));
    return content;
}

// Records an event as already accepted, with its auth_events, as ingestion would.
auto seed(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id, std::string const& type,
          std::optional<std::string> const& state_key, std::string const& sender, std::string const& json,
          std::vector<std::string> const& prev, std::vector<std::string> const& auth, std::uint64_t depth) -> void
{
    auto* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;
    store.events.push_back({event_id, room_id, sender, json, depth, depth + 1U, prev, auth, {}});
    auto const before = homeserver::compute_state_before(store, room_id, *policy, prev);
    REQUIRE(before.ok);
    auto const after = homeserver::compute_state_after(before.state, event_id, type, state_key);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev, after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
}

struct Room final
{
    std::string id{};
    std::string create{};
    std::string power_levels{};
};

// A room of `creator` with its create and power levels, known to this server.
[[nodiscard]] auto seed_room(HomeserverRuntime& runtime, std::string const& room_id, std::string const& creator) -> Room
{
    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, creator});
    runtime.database.rooms.push_back({room_id, creator, {}, false});

    auto const create_id = room_id + ":create";
    auto create = canonicaljson::Object{};
    create.push_back(canonicaljson::make_member("creator", canonicaljson::Value{creator}));
    create.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
    seed(runtime, room_id, create_id, "m.room.create", std::string{}, creator,
         build_event_json(room_id, "m.room.create", std::string{}, creator, std::move(create), {}, {}, 0, 1), {}, {},
         0U);

    auto const pl_id = room_id + ":pl";
    auto power = canonicaljson::Object{};
    power.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    auto users = canonicaljson::Object{};
    users.push_back(canonicaljson::make_member(creator, canonicaljson::Value{std::int64_t{100}}));
    power.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(users)}));
    seed(runtime, room_id, pl_id, "m.room.power_levels", std::string{}, creator,
         build_event_json(room_id, "m.room.power_levels", std::string{}, creator, std::move(power), {create_id},
                          {create_id}, 1, 2),
         {create_id}, {create_id}, 1U);
    return {room_id, create_id, pl_id};
}

auto seed_member(HomeserverRuntime& runtime, Room const& room, std::string const& suffix, std::string const& user,
                 std::string const& membership, std::string const& prev, std::vector<std::string> const& auth,
                 std::int64_t depth) -> std::string
{
    auto const event_id = room.id + ":" + suffix;
    seed(runtime, room.id, event_id, "m.room.member", user, user,
         build_event_json(room.id, "m.room.member", user, user, with_membership(membership), {prev}, auth, depth,
                          depth + 1),
         {prev}, auth, static_cast<std::uint64_t>(depth));
    return event_id;
}

[[nodiscard]] auto membership_row(HomeserverRuntime const& runtime, std::string const& room_id, std::string const& user)
    -> std::string
{
    auto const& rows = runtime.database.persistent_store.memberships;
    auto const row = std::ranges::find_if(rows, [&](database::PersistentMembership const& candidate) {
        return candidate.room_id == room_id && candidate.user_id == user;
    });
    return row == rows.end() ? std::string{} : row->membership;
}

[[nodiscard]] auto parse(std::string const& raw) -> canonicaljson::Value
{
    auto const parsed = canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    return parsed.value;
}

} // namespace

SCENARIO("A join PDU whose sender is not the user joining is rejected at receipt",
         "[gate-m][forged_join][pdu_ingestion]")
{
    GIVEN("a room whose local creator has left, and a message sent after they left")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        homeserver::wire_federation_callbacks(started.runtime);
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;

        auto const room = seed_room(runtime, "!forged:local.example.org", local_admin);
        auto const join = seed_member(runtime, room, "join", local_admin, "join", room.power_levels,
                                      {room.create, room.power_levels}, 2);
        auto const leave =
            seed_member(runtime, room, "leave", local_admin, "leave", join, {room.create, room.power_levels, join}, 3);
        store.memberships.push_back({room.id, local_admin, "leave", 4U});
        auto const after_leave = room.id + ":after-leave";
        auto body = canonicaljson::Object{};
        body.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"after the departure"}}));
        seed(runtime, room.id, after_leave, "m.room.message", std::nullopt, "@w:local.example.org",
             build_event_json(room.id, "m.room.message", std::nullopt, "@w:local.example.org", std::move(body), {leave},
                              {room.create, room.power_levels}, 4, 5),
             {leave}, {room.create, room.power_levels}, 4U);

        WHEN("another server sends a join for the creator, citing only the create event, at a very great depth")
        {
            auto const forged_id = std::string{"$forged:evil.example"};
            auto const depth = std::int64_t{1} << 40;
            auto const json = build_event_json(room.id, "m.room.member", local_admin, mallory, with_membership("join"),
                                               {room.create}, {room.create}, depth, 99'999'999'999);
            auto envelope = make_envelope(room.id, forged_id, "m.room.member", local_admin, mallory, {room.create},
                                          {room.create}, depth, json);
            envelope.origin = "evil.example";
            auto const result = homeserver::ingest_pdu_event(runtime, envelope);

            THEN("it is stored as rejected and changes nothing")
            {
                CHECK(result.status == PduIngestionStatus::rejected_auth);
                auto const stored = store.events.find(forged_id);
                REQUIRE(stored != store.events.end());
                CHECK(stored->status == "rejected");
                CHECK(membership_row(runtime, room.id, local_admin) == "leave");
                CHECK(database::find_current_state_event_id(store, room.id, "m.room.member", local_admin) == leave);
                auto const tips = database::find_forward_extremities(store, room.id);
                CHECK(std::ranges::find(tips, forged_id) == tips.end());
            }

            THEN("the departure limit still applies")
            {
                CHECK(sync::room_read_access_for(store, room.id, local_admin).kind == sync::RoomReadKind::as_of);
                auto visibility = sync::HistoryVisibility{store, local_admin};
                auto const message = store.events.find(after_leave);
                REQUIRE(message != store.events.end());
                CHECK_FALSE(visibility.can_see(*message));
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("An event citing a refused join is treated as citing any rejected event",
         "[gate-m][forged_join][pdu_ingestion]")
{
    GIVEN("a room of a remote creator with a joined local user, and a refused join for the creator")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        homeserver::wire_federation_callbacks(started.runtime);
        auto& runtime = started.runtime;

        auto const room = seed_room(runtime, "!citing:local.example.org", remote_creator);
        std::ignore = seed_member(runtime, room, "admin", local_admin, "join", room.power_levels,
                                  {room.create, room.power_levels}, 2);
        runtime.database.persistent_store.memberships.push_back({room.id, local_admin, "join", 3U});

        auto const forged_id = std::string{"$forged-cited:evil.example"};
        auto forged =
            make_envelope(room.id, forged_id, "m.room.member", remote_creator, mallory, {room.create}, {room.create}, 1,
                          build_event_json(room.id, "m.room.member", remote_creator, mallory, with_membership("join"),
                                           {room.create}, {room.create}, 1, 2));
        forged.origin = "evil.example";
        std::ignore = homeserver::ingest_pdu_event(runtime, forged);

        WHEN("a message names that join in its auth_events")
        {
            auto body = canonicaljson::Object{};
            body.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"citing it"}}));
            auto const json = build_event_json(room.id, "m.room.message", std::nullopt, remote_creator, std::move(body),
                                               {forged_id}, {room.create, forged_id}, 2, 3);
            auto citing = make_envelope(room.id, "$citing:remote.example.org", "m.room.message", std::nullopt,
                                        remote_creator, {forged_id}, {room.create, forged_id}, 2, json);
            citing.origin = "remote.example.org";
            auto const result = homeserver::ingest_pdu_event(runtime, citing);

            THEN("it is rejected")
            {
                CHECK(result.status == PduIngestionStatus::rejected_auth);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A creator's own first join is accepted", "[gate-m][forged_join][pdu_ingestion]")
{
    GIVEN("a room holding only its create event, whose local creator has a membership row")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        homeserver::wire_federation_callbacks(started.runtime);
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;

        auto const room_id = std::string{"!own:local.example.org"};
        store.rooms.push_back({room_id, local_admin});
        runtime.database.rooms.push_back({room_id, local_admin, {}, false});
        auto const create_id = room_id + ":create";
        auto create = canonicaljson::Object{};
        create.push_back(canonicaljson::make_member("creator", canonicaljson::Value{local_admin}));
        create.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
        seed(runtime, room_id, create_id, "m.room.create", std::string{}, local_admin,
             build_event_json(room_id, "m.room.create", std::string{}, local_admin, std::move(create), {}, {}, 0, 1),
             {}, {}, 0U);
        store.memberships.push_back({room_id, local_admin, "leave", 1U});

        WHEN("the creator's own join arrives")
        {
            auto const event_id = std::string{"$own:local.example.org"};
            auto const json = build_event_json(room_id, "m.room.member", local_admin, local_admin,
                                               with_membership("join"), {create_id}, {create_id}, 1, 2);
            auto envelope = make_envelope(room_id, event_id, "m.room.member", local_admin, local_admin, {create_id},
                                          {create_id}, 1, json);
            auto const result = homeserver::ingest_pdu_event(runtime, envelope);

            THEN("it is accepted and the creator is joined")
            {
                CHECK(result.status == PduIngestionStatus::accepted);
                CHECK(database::find_current_state_event_id(store, room_id, "m.room.member", local_admin) == event_id);
                CHECK(membership_row(runtime, room_id, local_admin) == "join");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("The membership acceptor refuses a join whose signed sender is not the user joining",
         "[gate-m][forged_join][membership_acceptor]")
{
    GIVEN("a room of a remote creator with a joined local user")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        homeserver::wire_federation_callbacks(started.runtime);
        auto& runtime = started.runtime;
        REQUIRE(runtime.federation.membership_acceptor != nullptr);

        auto const room = seed_room(runtime, "!acceptor:local.example.org", remote_creator);
        std::ignore = seed_member(runtime, room, "admin", local_admin, "join", room.power_levels,
                                  {room.create, room.power_levels}, 2);
        runtime.database.persistent_store.memberships.push_back({room.id, local_admin, "join", 3U});

        WHEN("the event's JSON names another sender than its envelope says")
        {
            auto const event_id = std::string{"$acceptor-forged:remote.example.org"};
            auto const json = build_event_json(room.id, "m.room.member", remote_creator, mallory,
                                               with_membership("join"), {room.create}, {room.create}, 1, 2);
            auto envelope = make_envelope(room.id, event_id, "m.room.member", remote_creator, remote_creator,
                                          {room.create}, {room.create}, 1, json);
            envelope.origin = "remote.example.org";
            auto const result = runtime.federation.membership_acceptor(federation::FederationEndpoint::send_join,
                                                                       room.id, event_id, envelope);

            THEN("it is refused with 403 and not stored")
            {
                CHECK_FALSE(result.accepted);
                CHECK(result.status == 403U);
                auto const& events = runtime.database.persistent_store.events;
                CHECK(events.find(event_id) == events.end());
            }
        }

        WHEN("the creator's own first join arrives")
        {
            auto const event_id = std::string{"$acceptor-own:remote.example.org"};
            auto const json = build_event_json(room.id, "m.room.member", remote_creator, remote_creator,
                                               with_membership("join"), {room.create}, {room.create}, 1, 2);
            auto envelope = make_envelope(room.id, event_id, "m.room.member", remote_creator, remote_creator,
                                          {room.create}, {room.create}, 1, json);
            envelope.origin = "remote.example.org";
            auto const result = runtime.federation.membership_acceptor(federation::FederationEndpoint::send_join,
                                                                       room.id, event_id, envelope);

            THEN("it is accepted")
            {
                CHECK(result.accepted);
                CHECK(result.status == 200U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A resident's send_join answer loses a join whose sender is not the user joining",
         "[gate-m][forged_join][send_join_answer]")
{
    GIVEN("an honest answer for a version 10 room, and a join for the creator sent by another user")
    {
        auto const* policy = rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto const room_id = std::string{"!answer:remote.example.org"};
        auto const id_of = [&](canonicaljson::Value const& value) {
            auto const made = events::make_reference_hash_event_id(value, *policy);
            REQUIRE(made.error.empty());
            return made.event_id;
        };
        auto const event = [&](std::string const& type, std::string const& state_key, std::string const& sender,
                               std::string const& content, std::string const& prev, std::string const& auth) {
            return parse(R"({"type":")" + type + R"(","state_key":")" + state_key + R"(","sender":")" + sender +
                         R"(","room_id":")" + room_id + R"(","depth":5,"origin_server_ts":950,"prev_events":[)" + prev +
                         R"(],"auth_events":[)" + auth + R"(],"content":)" + content + "}");
        };
        auto const quoted = [](std::string const& id) {
            return "\"" + id + "\"";
        };
        auto const create = event("m.room.create", "", remote_creator,
                                  R"({"room_version":"10","creator":")" + remote_creator + "\"}", "", "");
        auto const create_ref = quoted(id_of(create));
        auto const creator_join =
            event("m.room.member", remote_creator, remote_creator, R"({"membership":"join"})", create_ref, create_ref);
        auto const creator_join_ref = quoted(id_of(creator_join));
        auto const power =
            event("m.room.power_levels", "", remote_creator, R"({"users":{")" + remote_creator + R"(":100}})", "",
                  create_ref + "," + creator_join_ref);
        auto const power_ref = quoted(id_of(power));
        auto const rules = event("m.room.join_rules", "", remote_creator, R"({"join_rule":"public"})", "",
                                 create_ref + "," + creator_join_ref + "," + power_ref);
        auto const rules_ref = quoted(id_of(rules));
        auto const alice_join = event("m.room.member", "@alice:local.example.org", "@alice:local.example.org",
                                      R"({"membership":"join"})", "", create_ref + "," + power_ref + "," + rules_ref);
        auto const forged = event("m.room.member", remote_creator, "@bob:remote.example.org",
                                  R"({"membership":"join"})", create_ref, create_ref);
        auto const state = canonicaljson::Array{create, creator_join, power, rules};

        WHEN("the forged join is listed in the auth chain")
        {
            auto const answer = homeserver::authorize_send_join_answer(state, canonicaljson::Array{forged}, alice_join,
                                                                       *policy, room_id);

            THEN("it is dropped and the honest events stay")
            {
                CHECK(answer.refusal.empty());
                CHECK(answer.dropped == 1U);
                CHECK(answer.auth_chain.empty());
                CHECK(answer.state.size() == 4U);
            }
        }
    }
}
