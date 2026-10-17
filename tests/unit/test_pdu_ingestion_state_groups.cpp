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
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/deferred_pdu_retry.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
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

    // ADR-0064 phase B2: ingest_pdu_event now authorises against the PDU's
    // own named auth_events (spec step 4), so a real create/power_levels/
    // sender-member trio is required here — matching
    // seed_room_with_genesis_state_group's naming convention — for this
    // fixture to still be accepted, exactly as a real federating server's
    // auth_events selection would look for a room-admin-sent state event.
    auto const create_id = room_id + ":create";
    auto const pl_id = room_id + ":pl";
    auto const member_id = room_id + ":member";
    auto auth_event_ids = std::vector<std::string>{create_id, pl_id, member_id};

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
    auto auth_events_array = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth_events_array.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_events_array)}));

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
    env.auth_event_ids = std::move(auth_event_ids);
    env.json = serialized.output;
    return env;
}

constexpr auto deferred_pdu_origin = std::string_view{"remote.example.org"};

// A PDU as a remote server would send it: its event_id is the reference hash
// of its JSON (retries rebuild the envelope from the JSON, so the two must
// agree) and it names the server that sent it.
[[nodiscard]] auto make_sendable_pdu(std::string const& room_id, std::string const& label,
                                     std::string const& prev_event_id, std::int64_t ts) -> InboundPduEnvelope
{
    using namespace merovingian;

    auto envelope = make_topic_pdu(room_id, label, prev_event_id, ts);
    auto const parsed = canonicaljson::parse_lossless(envelope.json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto const* policy = rooms::find_room_version_policy(envelope.room_version);
    REQUIRE(policy != nullptr);
    auto const id = events::make_reference_hash_event_id(parsed.value, *policy);
    REQUIRE_FALSE(id.event_id.empty());
    envelope.event_id = id.event_id;
    envelope.origin = std::string{deferred_pdu_origin};
    return envelope;
}

[[nodiscard]] auto stores_event(merovingian::database::PersistentStore const& store, std::string const& event_id)
    -> bool
{
    return std::ranges::any_of(store.events, [&](merovingian::database::PersistentEvent const& event) {
        return event.event_id == event_id;
    });
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

SCENARIO("ingest_pdu_event does not store a PDU whose prev_event has no state group, and keeps nothing it cannot retry",
         "[pdu_ingestion][state_groups][federation][r03]")
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

        WHEN("a PDU whose prev_event was never recorded is ingested with no origin to backfill from")
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

            THEN("nothing is retained for a retry, because there is no server to retry against")
            {
                REQUIRE(started.runtime.database.persistent_store.deferred_pdus.empty());
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: server-server-api.md, "Transactions" -- the sender is told a PDU was
// handled and does not send it again; "Gap filling" -- a server that lacks a
// PDU's prev_events fetches them. A PDU this server cannot yet place must
// therefore be kept and placed later, not dropped with a 200.
SCENARIO("A PDU whose history cannot be fetched is retained and not stored", "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime seeded with room genesis that cannot reach any remote server")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!defer:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);

        WHEN("a PDU naming a prev_event this server has never seen arrives from a remote server")
        {
            auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);
            auto const& store = started.runtime.database.persistent_store;

            THEN("it is reported as deferred, meaning retained and to be retried")
            {
                REQUIRE(result.status == PduIngestionStatus::deferred);
            }

            THEN("the event is not in the events table")
            {
                REQUIRE_FALSE(stores_event(store, envelope.event_id));
            }

            THEN("exactly one deferral names it, with the room, the origin and the PDU as received")
            {
                REQUIRE(store.deferred_pdus.size() == 1U);
                auto const& row = store.deferred_pdus.front();
                REQUIRE(row.event_id == envelope.event_id);
                REQUIRE(row.room_id == room_id);
                REQUIRE(row.origin == deferred_pdu_origin);
                REQUIRE(row.pdu_json == envelope.json);
                REQUIRE(row.received_at_ms > 0);
                REQUIRE(row.attempts == 0U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A retained PDU is accepted once the event it was waiting for has arrived", "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime holding a retained PDU whose parent has not arrived")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!arrive:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto const parent = make_sendable_pdu(room_id, "parent", room_id + ":member", 100);
        auto const child = make_sendable_pdu(room_id, "child", parent.event_id, 200);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, child).status ==
                PduIngestionStatus::deferred);

        WHEN("the parent is accepted and the retry job then runs")
        {
            auto const parent_result = merovingian::homeserver::ingest_pdu_event(started.runtime, parent);
            REQUIRE(parent_result.status == PduIngestionStatus::accepted);
            std::ignore =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});
            auto const& store = started.runtime.database.persistent_store;

            THEN("the retained PDU is in the events table as accepted")
            {
                auto const it =
                    std::ranges::find_if(store.events, [&](merovingian::database::PersistentEvent const& e) {
                        return e.event_id == child.event_id;
                    });
                REQUIRE(it != store.events.end());
                REQUIRE(it->status == "accepted");
            }

            THEN("the deferral is gone")
            {
                REQUIRE(store.deferred_pdus.empty());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A retained PDU survives a restart", "[pdu_ingestion][federation][r03]")
{
    GIVEN("a database file holding a retained PDU written by a runtime that has since stopped")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const room_id = std::string{"!restart:local.example.org"};
        auto event_id = std::string{};
        {
            auto first = merovingian::homeserver::start_runtime(config_with_sqlite(path));
            REQUIRE(first.started);
            merovingian::homeserver::wire_federation_callbacks(first.runtime);
            first.runtime.discovery_network.reset();
            first.runtime.cached_discovery.reset();
            seed_room_with_genesis_state_group(first.runtime, room_id);
            auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
            event_id = envelope.event_id;
            REQUIRE(merovingian::homeserver::ingest_pdu_event(first.runtime, envelope).status ==
                    PduIngestionStatus::deferred);
        }

        WHEN("the runtime is started again on the same database file")
        {
            auto second = merovingian::homeserver::start_runtime(config_with_sqlite(path));
            REQUIRE(second.started);

            THEN("the retained PDU is loaded with its room, origin and attempt count")
            {
                auto const& rows = second.runtime.database.persistent_store.deferred_pdus;
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().event_id == event_id);
                REQUIRE(rows.front().room_id == room_id);
                REQUIRE(rows.front().origin == deferred_pdu_origin);
                REQUIRE(rows.front().attempts == 0U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A retained PDU that has waited too long or been tried too often is dropped and audited",
         "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime holding a retained PDU")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!expire:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, envelope).status ==
                PduIngestionStatus::deferred);
        auto& row = started.runtime.database.persistent_store.deferred_pdus.front();

        auto const limit = GENERATE(as<std::string>{}, "attempts", "age");
        CAPTURE(limit);
        if (limit == "attempts")
        {
            row.attempts = merovingian::database::max_deferred_pdu_attempts;
        }
        else
        {
            row.received_at_ms = 1;
        }

        WHEN("the retry job runs")
        {
            std::ignore =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});

            THEN("the deferral is gone and the event was never stored")
            {
                REQUIRE(started.runtime.database.persistent_store.deferred_pdus.empty());
                REQUIRE_FALSE(stores_event(started.runtime.database.persistent_store, envelope.event_id));
            }

            THEN("the loss is audited")
            {
                REQUIRE(std::ranges::any_of(started.runtime.database.audit_events, [](auto const& event) {
                    return event.event_type == "federation.pdu_deferral_expired";
                }));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A retained PDU that still cannot be placed waits out a back-off before it is tried again",
         "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime holding a retained PDU and no other work for the retry job")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!backoff:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);

        WHEN("there is nothing retained")
        {
            auto const delay =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});

            THEN("the job is told to look again in five minutes")
            {
                REQUIRE(delay == std::chrono::minutes{5});
            }
        }

        WHEN("the retry job runs twice in a row and the PDU is still unplaceable")
        {
            auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
            REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, envelope).status ==
                    PduIngestionStatus::deferred);
            auto const first =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});
            auto const attempts_after_first = started.runtime.database.persistent_store.deferred_pdus.front().attempts;
            auto const second =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});
            auto const& rows = started.runtime.database.persistent_store.deferred_pdus;

            THEN("the first run counts one attempt and the second finds it not yet due")
            {
                REQUIRE(attempts_after_first == 1U);
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().attempts == 1U);
            }

            THEN("the job is asked back no sooner than 25 seconds and no later than the back-off cap")
            {
                REQUIRE(first >= std::chrono::seconds{25});
                REQUIRE(first <= std::chrono::hours{1});
                REQUIRE(second >= std::chrono::seconds{25});
                REQUIRE(second <= std::chrono::hours{1});
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Accepting the event a retained PDU waits for wakes the retry job and makes it due at once",
         "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime whose retry job has already failed once on a retained PDU")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!wake:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto const parent = make_sendable_pdu(room_id, "parent", room_id + ":member", 100);
        auto const child = make_sendable_pdu(room_id, "child", parent.event_id, 200);
        auto const unrelated = make_sendable_pdu(room_id, "unrelated", room_id + ":member", 300);
        auto wakes = 0;
        started.runtime.deferred_pdu_retry_wake = [&wakes]() {
            ++wakes;
        };
        REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, child).status ==
                PduIngestionStatus::deferred);
        std::ignore =
            merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});
        REQUIRE(started.runtime.database.persistent_store.deferred_pdus.size() == 1U);
        REQUIRE(wakes == 0);

        WHEN("an unrelated PDU is accepted for the room")
        {
            REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, unrelated).status ==
                    PduIngestionStatus::accepted);
            std::ignore =
                merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});

            THEN("the job is not woken and the retained PDU keeps waiting out its back-off")
            {
                REQUIRE(wakes == 0);
                REQUIRE(started.runtime.database.persistent_store.deferred_pdus.size() == 1U);
                REQUIRE(started.runtime.database.persistent_store.deferred_pdus.front().attempts == 1U);
            }
        }

        WHEN("the parent it names is accepted")
        {
            REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, parent).status ==
                    PduIngestionStatus::accepted);

            THEN("the job is woken")
            {
                REQUIRE(wakes == 1);
            }

            AND_WHEN("the retry job runs straight away")
            {
                std::ignore =
                    merovingian::homeserver::retry_deferred_pdus(started.runtime, merovingian::homeserver::StopFlag{});

                THEN("the retained PDU is placed without waiting for its back-off")
                {
                    REQUIRE(stores_event(started.runtime.database.persistent_store, child.event_id));
                    REQUIRE(started.runtime.database.persistent_store.deferred_pdus.empty());
                }
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Ingesting the same unplaceable PDU again keeps a single retained copy", "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime that has already retained a PDU")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!again:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, envelope).status ==
                PduIngestionStatus::deferred);
        auto& first_row = started.runtime.database.persistent_store.deferred_pdus.front();
        first_row.received_at_ms = 12345;

        WHEN("the same PDU arrives again")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);
            auto const& rows = started.runtime.database.persistent_store.deferred_pdus;

            THEN("it is still reported as retained")
            {
                REQUIRE(result.status == PduIngestionStatus::deferred);
            }

            THEN("there is one row, and it keeps the time the PDU was first received")
            {
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().received_at_ms == 12345);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A PDU is not retained once the retained set is full", "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime whose retained set is at one of its limits")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!full:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto& rows = started.runtime.database.persistent_store.deferred_pdus;

        auto const limit = GENERATE(as<std::string>{}, "per room", "in total", "bytes");
        CAPTURE(limit);
        if (limit == "per room")
        {
            for (auto i = std::size_t{0U}; i < merovingian::database::max_deferred_pdus_per_room; ++i)
            {
                rows.push_back(
                    {"$fill" + std::to_string(i), room_id, std::string{deferred_pdu_origin}, "{}", 1000, 0U});
            }
        }
        else if (limit == "in total")
        {
            for (auto i = std::size_t{0U}; i < merovingian::database::max_deferred_pdus_total; ++i)
            {
                rows.push_back({"$fill" + std::to_string(i), "!other" + std::to_string(i % 50U) + ":local.example.org",
                                std::string{deferred_pdu_origin}, "{}", 1000, 0U});
            }
        }
        else
        {
            rows.push_back({"$fill", "!other:local.example.org", std::string{deferred_pdu_origin},
                            std::string(merovingian::database::max_deferred_pdu_json_bytes, 'x'), 1000, 0U});
        }
        auto const rows_before = rows.size();

        WHEN("another unplaceable PDU arrives")
        {
            auto const envelope = make_sendable_pdu(room_id, "orphan", room_id + ":never-recorded", 100);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is reported as missing_prev_state, not retained")
            {
                REQUIRE(result.status == PduIngestionStatus::missing_prev_state);
                REQUIRE(rows.size() == rows_before);
            }

            THEN("it is not stored either")
            {
                REQUIRE_FALSE(stores_event(started.runtime.database.persistent_store, envelope.event_id));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("The retry job places a retained PDU as soon as its parent arrives, and detaches from the runtime on stop",
         "[pdu_ingestion][federation][r03]")
{
    GIVEN("a runtime with a started retry job and a retained PDU whose parent has not arrived")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.discovery_network.reset();
        started.runtime.cached_discovery.reset();

        auto const room_id = std::string{"!job:local.example.org"};
        seed_room_with_genesis_state_group(started.runtime, room_id);
        auto const parent = make_sendable_pdu(room_id, "parent", room_id + ":member", 100);
        auto const child = make_sendable_pdu(room_id, "child", parent.event_id, 200);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, child).status ==
                PduIngestionStatus::deferred);

        auto job = merovingian::homeserver::DeferredPduRetryJob{started.runtime};
        REQUIRE(job.start());

        WHEN("the parent is ingested and the job is left to run")
        {
            REQUIRE(merovingian::homeserver::ingest_pdu_event(started.runtime, parent).status ==
                    PduIngestionStatus::accepted);
            auto placed = false;
            for (auto i = 0; i < 200 && !placed; ++i)
            {
                {
                    auto const guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{started.runtime.mutex};
                    placed = stores_event(started.runtime.database.persistent_store, child.event_id) &&
                             started.runtime.database.persistent_store.deferred_pdus.empty();
                }
                if (!placed)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{50});
                }
            }

            THEN("the retained PDU is stored and its deferral removed without any explicit retry call")
            {
                REQUIRE(placed);
            }
        }

        WHEN("the job is stopped")
        {
            job.stop();

            THEN("the runtime no longer holds a wake hook that points at it")
            {
                auto const guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{started.runtime.mutex};
                REQUIRE_FALSE(static_cast<bool>(started.runtime.deferred_pdu_retry_wake));
            }
        }

        job.stop();
        std::filesystem::remove(path);
    }
}
