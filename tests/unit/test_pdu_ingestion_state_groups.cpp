// SPDX-License-Identifier: GPL-3.0-or-later

// End-to-end proof that merovingian::homeserver::ingest_pdu_event — the
// production federation PDU sink (src/homeserver/local_http_router.cpp) —
// is actually wired to ADR-0064 phase B1's state bookkeeping, not just the
// helper functions in isolation (see tests/unit/test_state_bookkeeping.cpp
// for those). Tags: [pdu_ingestion][state_groups].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU", "Transactions" (a rejected/unprocessable PDU must not
// fail the whole transaction).

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-pdu-state-groups-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

// Seeds a room whose genesis (create/power_levels/member) is recorded both
// as ordinary events+current_state (so build_pdu_auth_event_map's auth
// checks succeed, matching test_federation_pdu_ingest_concurrency.cpp's
// seed_room) and as ADR-0064 phase-A state-group/forward-extremity rows
// (mirroring what migration 015 seeds for a pre-existing room), so a real
// inbound PDU whose prev_event is the genesis tip finds a state group.
auto seed_room_with_genesis_state_group(HomeserverRuntime& runtime, std::string const& room_id) -> void
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto& local = runtime.database.rooms;

    store.rooms.push_back({room_id, "@admin:local.example.org"});
    local.push_back({room_id, "@admin:local.example.org", {}, {}, false});

    auto const create_id = room_id + ":create";
    auto const pl_id = room_id + ":pl";
    auto const member_id = room_id + ":member";

    auto const make_json = [&](std::string_view type, std::string_view state_key, std::string_view sender,
                               canonicaljson::Object content, std::int64_t depth, std::int64_t ts) -> std::string {
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));
        auto obj = canonicaljson::Object{};
        obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
        obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
        obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
        obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
        obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{type}}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
        return serialized.output;
    };

    auto create_content = canonicaljson::Object{};
    create_content.push_back(
        canonicaljson::make_member("creator", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
    auto const create_json =
        make_json("m.room.create", "", "@admin:local.example.org", std::move(create_content), 0, 1);
    store.events.push_back({create_id, room_id, "@admin:local.example.org", create_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.create", "", create_id});

    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    auto pl_users = canonicaljson::Object{};
    pl_users.push_back(canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(pl_users)}));
    auto const pl_json = make_json("m.room.power_levels", "", "@admin:local.example.org", std::move(pl_content), 1, 2);
    store.events.push_back({pl_id, room_id, "@admin:local.example.org", pl_json, 1U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.power_levels", "", pl_id});

    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json = make_json("m.room.member", "@admin:local.example.org", "@admin:local.example.org",
                                       std::move(member_content), 2, 3);
    store.events.push_back({member_id, room_id, "@admin:local.example.org", member_json, 2U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", "@admin:local.example.org", member_id});
    store.memberships.push_back({room_id, "@admin:local.example.org", "join", 0U});

    auto const genesis_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",                         create_id},
        {"", "m.room.power_levels", "",                         pl_id    },
        {"", "m.room.member",       "@admin:local.example.org", member_id},
    };
    auto const group_id =
        database::create_or_reuse_state_group(store, room_id, room_id + ":genesis-group", std::nullopt, genesis_state);
    REQUIRE(group_id.has_value());
    REQUIRE(database::set_event_state_group(store, member_id, *group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, member_id, {}, true));
}

[[nodiscard]] auto make_topic_pdu(std::string const& room_id, std::string const& event_id,
                                  std::string const& prev_event_id, std::int64_t ts) -> InboundPduEnvelope
{
    using namespace merovingian;

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{std::string{"t-" + event_id}}));

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.topic"}}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{3}}));
    auto prev_events = canonicaljson::Array{};
    prev_events.push_back(canonicaljson::Value{prev_event_id});
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_events)}));
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));

    auto const hash = events::make_content_hash(canonicaljson::Value{obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto env = InboundPduEnvelope{};
    env.event_id = event_id;
    env.room_id = room_id;
    env.room_version = "10";
    env.sender = "@admin:local.example.org";
    env.event_type = "m.room.topic";
    env.state_key = std::string{};
    env.origin_server_ts = ts;
    env.depth = 3U;
    env.prev_event_ids = {prev_event_id};
    env.json = serialized.output;
    return env;
}

} // namespace

SCENARIO("ingest_pdu_event resolves two concurrent state forks identically regardless of arrival order",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("two fresh runtimes seeded with identical room genesis")
    {
        auto const path_ab = unique_sqlite_path();
        std::filesystem::remove(path_ab);
        auto started_ab = merovingian::homeserver::start_runtime(config_with_sqlite(path_ab));
        REQUIRE(started_ab.started);
        merovingian::homeserver::wire_federation_callbacks(started_ab.runtime);

        auto const path_ba = unique_sqlite_path();
        std::filesystem::remove(path_ba);
        auto started_ba = merovingian::homeserver::start_runtime(config_with_sqlite(path_ba));
        REQUIRE(started_ba.started);
        merovingian::homeserver::wire_federation_callbacks(started_ba.runtime);

        auto const room_id = std::string{"!fork:local.example.org"};
        seed_room_with_genesis_state_group(started_ab.runtime, room_id);
        seed_room_with_genesis_state_group(started_ba.runtime, room_id);

        auto const tip = room_id + ":member";
        auto const topic_a = make_topic_pdu(room_id, "$topic_a:local.example.org", tip, 100);
        auto const topic_b = make_topic_pdu(room_id, "$topic_b:local.example.org", tip, 200);

        WHEN("the two PDUs are ingested in opposite orders on the two runtimes")
        {
            auto const result_a1 = merovingian::homeserver::ingest_pdu_event(started_ab.runtime, topic_a);
            auto const result_b1 = merovingian::homeserver::ingest_pdu_event(started_ab.runtime, topic_b);
            auto const result_b2 = merovingian::homeserver::ingest_pdu_event(started_ba.runtime, topic_b);
            auto const result_a2 = merovingian::homeserver::ingest_pdu_event(started_ba.runtime, topic_a);

            THEN("both PDUs are accepted on both runtimes")
            {
                REQUIRE(result_a1.status == PduIngestionStatus::accepted);
                REQUIRE(result_b1.status == PduIngestionStatus::accepted);
                REQUIRE(result_b2.status == PduIngestionStatus::accepted);
                REQUIRE(result_a2.status == PduIngestionStatus::accepted);
            }

            THEN("the resulting current_state m.room.topic winner is identical on both runtimes")
            {
                auto const topic_in = [&](merovingian::homeserver::HomeserverRuntime const& rt) -> std::string {
                    for (auto const& entry : rt.database.persistent_store.state)
                    {
                        if (entry.room_id == room_id && entry.event_type == "m.room.topic")
                        {
                            return entry.event_id;
                        }
                    }
                    return {};
                };
                auto const winner_ab = topic_in(started_ab.runtime);
                auto const winner_ba = topic_in(started_ba.runtime);
                REQUIRE_FALSE(winner_ab.empty());
                REQUIRE(winner_ab == winner_ba);
            }
        }

        std::filesystem::remove(path_ab);
        std::filesystem::remove(path_ba);
    }
}

SCENARIO("ingest_pdu_event rejects a PDU whose prev_event has no state group without storing it",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a fresh runtime seeded with room genesis")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!gap:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);

        WHEN("a PDU whose prev_event was never recorded is ingested")
        {
            auto const envelope =
                make_topic_pdu(room_id, "$orphan:local.example.org", room_id + ":never-recorded", 100);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is reported as missing_prev_state, not accepted or rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
            }

            THEN("the event is not persisted")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                REQUIRE(std::ranges::none_of(events, [](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$orphan:local.example.org";
                }));
            }
        }

        std::filesystem::remove(path);
    }
}
