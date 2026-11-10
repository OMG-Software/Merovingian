// SPDX-License-Identifier: GPL-3.0-or-later

// F-18, ADR-0326: a retained federation PDU is woken through an index of the event IDs it is missing,
// not by searching every retained row's JSON for the ID as text. Tags: [deferred_pdu][federation].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md "Backfilling and retrieving missing events" (a
// server that lacks a PDU's prev_events fetches them and then places the PDU).

#include "../support/MasterKey.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentDeferredPdu.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/DeferredPduRetry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::PersistentDeferredPdu;
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-deferred-wake-" + std::to_string(now) + ".sqlite3");
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

[[nodiscard]] auto pdu_json(std::string const& body, std::vector<std::string> const& prev_events,
                            std::vector<std::string> const& auth_events) -> std::string
{
    auto const list = [](std::vector<std::string> const& ids) {
        auto text = std::string{"["};
        for (auto const& id : ids)
        {
            text += (text.size() > 1U ? ",\"" : "\"") + id + "\"";
        }
        return text + "]";
    };
    return R"({"auth_events":)" + list(auth_events) + R"(,"content":{"body":")" + body + R"("},"prev_events":)" +
           list(prev_events) + R"(,"type":"m.room.message"})";
}

[[nodiscard]] auto retained(std::string event_id, std::string room_id, std::string json) -> PersistentDeferredPdu
{
    return {std::move(event_id), std::move(room_id), "remote.example.org", std::move(json), 1000, 0U};
}

} // namespace

SCENARIO("Waking retained PDUs touches only the rows that are missing the stored event", "[deferred_pdu][federation]")
{
    GIVEN("retained PDUs, all scheduled for a later retry")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;

        auto const room = std::string{"!room:local.example.org"};
        auto const other_room = std::string{"!other:local.example.org"};
        auto const awaited = std::string{"$awaited"};
        // Names the awaited event as a prev_event.
        REQUIRE(upsert_deferred_pdu(store, retained("$waits-prev", room, pdu_json("x", {awaited}, {"$auth-a"}))) ==
                merovingian::database::DeferredPduUpsert::inserted);
        // Names it as an auth_event.
        REQUIRE(upsert_deferred_pdu(store, retained("$waits-auth", room, pdu_json("x", {"$prev-b"}, {awaited}))) ==
                merovingian::database::DeferredPduUpsert::inserted);
        // Only mentions the ID as text in its content, and waits for something else.
        REQUIRE(upsert_deferred_pdu(store, retained("$mentions-only", room,
                                                    pdu_json("see " + awaited + " for details", {"$prev-c"}, {}))) ==
                merovingian::database::DeferredPduUpsert::inserted);
        // Waits for the same ID, but in another room.
        REQUIRE(upsert_deferred_pdu(store, retained("$other-room", other_room, pdu_json("x", {awaited}, {}))) ==
                merovingian::database::DeferredPduUpsert::inserted);
        // Is itself the event stored: never woken by its own arrival.
        REQUIRE(upsert_deferred_pdu(store, retained(awaited, room, pdu_json("x", {"$prev-d"}, {}))) ==
                merovingian::database::DeferredPduUpsert::inserted);

        auto const later = std::chrono::steady_clock::now() + std::chrono::hours{1};
        for (auto const& row : store.deferred_pdus)
        {
            runtime.deferred_pdu_next_attempt[row.event_id] = later;
        }
        auto wakes = 0;
        runtime.deferred_pdu_retry_wake = [&wakes]() {
            ++wakes;
        };

        WHEN("the awaited event is stored in the room")
        {
            merovingian::homeserver::wake_deferred_pdus_waiting_for(runtime, room, awaited);

            THEN("the rows naming it in prev_events or auth_events are due at once")
            {
                REQUIRE_FALSE(runtime.deferred_pdu_next_attempt.contains("$waits-prev"));
                REQUIRE_FALSE(runtime.deferred_pdu_next_attempt.contains("$waits-auth"));
            }
            THEN("a row that only has the ID as text, a row of another room and the event's own row keep waiting")
            {
                REQUIRE(runtime.deferred_pdu_next_attempt.contains("$mentions-only"));
                REQUIRE(runtime.deferred_pdu_next_attempt.contains("$other-room"));
                REQUIRE(runtime.deferred_pdu_next_attempt.contains(awaited));
            }
            THEN("the retry job is woken once")
            {
                REQUIRE(wakes == 1);
            }
        }

        WHEN("an event no retained PDU is missing is stored")
        {
            merovingian::homeserver::wake_deferred_pdus_waiting_for(runtime, room, "$nobody-waits");

            THEN("no row is made due and the retry job is not woken")
            {
                REQUIRE(runtime.deferred_pdu_next_attempt.size() == 5U);
                REQUIRE(wakes == 0);
            }
        }

        WHEN("a waiting row is removed and the event arrives")
        {
            REQUIRE(merovingian::database::remove_deferred_pdu(store, "$waits-prev"));
            runtime.deferred_pdu_next_attempt["$waits-prev"] = later;
            merovingian::homeserver::wake_deferred_pdus_waiting_for(runtime, room, awaited);

            THEN("the removed row is not woken again")
            {
                REQUIRE(runtime.deferred_pdu_next_attempt.contains("$waits-prev"));
                REQUIRE_FALSE(runtime.deferred_pdu_next_attempt.contains("$waits-auth"));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("The index of what retained PDUs wait for is the same after a restart", "[deferred_pdu][federation]")
{
    GIVEN("a retained PDU in a database that is closed and opened again")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const room = std::string{"!room:local.example.org"};
        {
            auto first = merovingian::homeserver::start_runtime(config_with_sqlite(path));
            REQUIRE(first.started);
            REQUIRE(upsert_deferred_pdu(first.runtime.database.persistent_store,
                                        retained("$waits", room, pdu_json("x", {"$awaited"}, {}))) ==
                    merovingian::database::DeferredPduUpsert::inserted);
        }

        auto second = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(second.started);
        auto& runtime = second.runtime;
        REQUIRE(runtime.database.persistent_store.deferred_pdus.size() == 1U);
        runtime.deferred_pdu_next_attempt["$waits"] = std::chrono::steady_clock::now() + std::chrono::hours{1};

        WHEN("the awaited event is stored")
        {
            merovingian::homeserver::wake_deferred_pdus_waiting_for(runtime, room, "$awaited");

            THEN("the reloaded row is woken")
            {
                REQUIRE_FALSE(runtime.deferred_pdu_next_attempt.contains("$waits"));
            }
        }

        std::filesystem::remove(path);
    }
}
