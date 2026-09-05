// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-pdu-concurrency-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto make_seed_event_json(std::string_view room_id, std::string_view event_type,
                                        std::string_view state_key, std::string_view sender,
                                        merovingian::canonicaljson::Object content, std::int64_t depth,
                                        std::int64_t origin_server_ts) -> std::string
{
    using namespace merovingian;

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    event_obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{origin_server_ts}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
    event_obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{event_type}}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

auto seed_room(merovingian::homeserver::HomeserverRuntime& runtime, std::string_view room_id) -> void
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto& local = runtime.database.rooms;

    store.rooms.push_back({std::string{room_id}, "@admin:local.example.org"});
    local.push_back({std::string{room_id},
                     "@admin:local.example.org",
                     std::vector<std::string>{"@alice:remote.example.org"},
                     {},
                     false});
    store.memberships.push_back({std::string{room_id}, "@alice:remote.example.org", "join", 0U});

    auto const create_id = std::string{room_id} + ":create";
    auto const pl_id = std::string{room_id} + ":pl";
    auto const member_id = std::string{room_id} + ":member";

    auto create_content = canonicaljson::Object{};
    create_content.push_back(
        canonicaljson::make_member("creator", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"12"}}));
    auto const create_json =
        make_seed_event_json(room_id, "m.room.create", "", "@admin:local.example.org", std::move(create_content), 0, 1);
    store.events.push_back(
        {create_id, std::string{room_id}, "@admin:local.example.org", create_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.create", "", create_id});

    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("ban", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(
        canonicaljson::make_member("events_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    pl_content.push_back(canonicaljson::make_member("invite", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(canonicaljson::make_member("kick", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(canonicaljson::make_member("redact", canonicaljson::Value{static_cast<std::int64_t>(50)}));
    pl_content.push_back(
        canonicaljson::make_member("state_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    pl_content.push_back(
        canonicaljson::make_member("users_default", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    auto pl_users = canonicaljson::Object{};
    pl_users.push_back(
        canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{static_cast<std::int64_t>(100)}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(pl_users)}));
    auto const pl_json = make_seed_event_json(room_id, "m.room.power_levels", "", "@admin:local.example.org",
                                              std::move(pl_content), 1, 2);
    store.events.push_back({pl_id, std::string{room_id}, "@admin:local.example.org", pl_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.power_levels", "", pl_id});

    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json = make_seed_event_json(room_id, "m.room.member", "@alice:remote.example.org",
                                                  "@alice:remote.example.org", std::move(member_content), 2, 3);
    store.events.push_back(
        {member_id, std::string{room_id}, "@alice:remote.example.org", member_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({std::string{room_id}, "m.room.member", "@alice:remote.example.org", member_id});
}

[[nodiscard]] auto make_message_pdu(std::string_view room_id, std::size_t seq)
    -> merovingian::federation::InboundPduEnvelope
{
    using namespace merovingian;

    auto content = canonicaljson::Object{};
    content.push_back(
        canonicaljson::make_member("body", canonicaljson::Value{std::string{"hello "} + std::to_string(seq)}));
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(
        canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@alice:remote.example.org"}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(
        canonicaljson::make_member("origin_server_ts", canonicaljson::Value{static_cast<std::int64_t>(1000 + seq)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(3)}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));

    auto const hash = events::make_content_hash(canonicaljson::Value{event_obj});
    REQUIRE(hash.error.empty());

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto env = federation::InboundPduEnvelope{};
    env.event_id = std::string{room_id} + ":message:" + std::to_string(seq);
    env.room_id = std::string{room_id};
    env.room_version = "12";
    env.sender = "@alice:remote.example.org";
    env.event_type = "m.room.message";
    env.origin_server_ts = static_cast<std::int64_t>(1000 + seq);
    env.depth = 3U;
    env.json = serialized.output;
    return env;
}

} // namespace

SCENARIO("Concurrent inbound PDU ingestion across distinct rooms persists all events and preserves room ordering",
         "[federation][concurrency][pdu-ingest]")
{
    GIVEN("a started runtime with several pre-seeded rooms and wired federation callbacks")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);

        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(sqlite_path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto constexpr room_count = std::size_t{8U};
        auto constexpr events_per_room = std::size_t{4U};
        for (std::size_t i = 0U; i < room_count; ++i)
        {
            seed_room(runtime, "!room" + std::to_string(i) + ":local.example.org");
        }

        WHEN("each room ingests several pre-built messages concurrently")
        {
            // Build all envelopes on the main thread so that Catch2 assertions
            // (used by make_message_pdu) stay single-threaded. Workers only
            // mutate the atomic accepted counter.
            auto room_envelopes = std::vector<std::vector<merovingian::federation::InboundPduEnvelope>>{};
            room_envelopes.reserve(room_count);
            for (std::size_t room_index = 0U; room_index < room_count; ++room_index)
            {
                auto room_id = std::string{"!room"} + std::to_string(room_index) + ":local.example.org";
                auto envelopes = std::vector<merovingian::federation::InboundPduEnvelope>{};
                envelopes.reserve(events_per_room);
                for (std::size_t seq = 0U; seq < events_per_room; ++seq)
                {
                    envelopes.push_back(make_message_pdu(room_id, seq));
                }
                room_envelopes.push_back(std::move(envelopes));
            }

            auto accepted = std::atomic<std::size_t>{0U};
            auto threads = std::vector<std::thread>{};
            threads.reserve(room_count);

            for (std::size_t room_index = 0U; room_index < room_count; ++room_index)
            {
                threads.emplace_back([&runtime, &room_envelopes, room_index, &accepted]() {
                    for (auto const& env : room_envelopes[room_index])
                    {
                        auto const result = merovingian::homeserver::ingest_pdu_event(runtime, env);
                        if (result.status == merovingian::federation::PduIngestionStatus::accepted)
                        {
                            accepted.fetch_add(1U, std::memory_order_relaxed);
                        }
                    }
                });
            }

            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("every message is accepted and persisted")
            {
                REQUIRE(accepted.load() == room_count * events_per_room);

                auto const expected_room_events = room_count * events_per_room;
                auto const persisted_room_events = std::ranges::count_if(
                    runtime.database.persistent_store.events, [](merovingian::database::PersistentEvent const& event) {
                        return event.json.find("\"type\":\"m.room.message\"") != std::string::npos;
                    });
                REQUIRE(static_cast<std::size_t>(persisted_room_events) == expected_room_events);
            }

            std::filesystem::remove(sqlite_path);
        }
    }
}
