// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RoomService.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace
{
class NulHttpSqliteCleanup final
{
public:
    explicit NulHttpSqliteCleanup(std::filesystem::path path)
        : path_{std::move(path)}
    {
    }
    ~NulHttpSqliteCleanup() noexcept
    {
        auto error = std::error_code{};
        for (auto const suffix : {"", "-wal", "-shm", "-journal"})
        {
            std::ignore = std::filesystem::remove(path_.string() + suffix, error);
        }
    }
    NulHttpSqliteCleanup(NulHttpSqliteCleanup const&) = delete;
    auto operator=(NulHttpSqliteCleanup const&) -> NulHttpSqliteCleanup& = delete;

private:
    std::filesystem::path path_;
};

// Compare only business rows; a refusal may legitimately append an audit row.
// Length-prefix fields and compare booleans so no event payload is printed.
[[nodiscard]] auto nul_business_snapshot(merovingian::database::PersistentStore const& store)
    -> std::vector<std::string>
{
    auto rows = std::vector<std::string>{};
    auto const append = [&rows](std::vector<std::string> const& fields) {
        auto encoded = std::string{};
        for (auto const& field : fields)
        {
            encoded += std::to_string(field.size()) + ":" + field;
        }
        rows.push_back(std::move(encoded));
    };
    for (auto const& row : store.rooms)
        append({"room", row.room_id, row.creator_user_id, std::to_string(row.directory_public)});
    for (auto const& row : store.memberships)
        append({"membership", row.room_id, row.user_id, row.membership, std::to_string(row.stream_ordering)});
    for (auto const& row : store.invites)
    {
        append({"invite", row.room_id, row.user_id, row.sender_user_id, row.event_id, row.signed_event_json,
                std::to_string(row.stream_ordering)});
        for (auto const& state : row.invite_state_events_json)
        {
            append({"invite-state", row.event_id, state});
        }
    }
    for (auto const& row : store.events)
        append({"event", row.event_id, row.room_id, row.sender_user_id, row.json, std::to_string(row.depth),
                std::to_string(row.stream_ordering), row.status});
    for (auto const& row : store.state)
        append({"state", row.room_id, row.event_type, row.state_key, row.event_id});
    for (auto const& row : store.state_transitions)
        append({"transition", row.room_id, row.event_type, row.state_key, row.event_id, row.previous_event_id});
    for (auto const& row : store.state_groups)
        append({"group", row.state_group_id, row.room_id, row.parent_state_group_id.value_or(""),
                std::to_string(row.delta_depth)});
    for (auto const& row : store.state_group_state)
        append({"group-state", row.state_group_id, row.event_type, row.state_key, row.event_id});
    for (auto const& row : store.event_state_groups)
        append({"event-group", row.event_id, row.state_group_id});
    for (auto const& row : store.event_edges)
        append({"edge", row.event_id, row.prev_event_id});
    for (auto const& row : store.event_auth)
        append({"auth", row.event_id, row.auth_event_id});
    for (auto const& row : store.event_signatures)
        append({"signature", row.event_id, row.server_name, row.key_id, row.signature});
    for (auto const& row : store.forward_extremities)
        append({"extremity", row.room_id, row.event_id});
    append({"event-watermark", std::to_string(store.event_stream_watermark)});
    append({"sync-watermark", std::to_string(store.next_sync_stream_id)});
    std::ranges::sort(rows);
    return rows;
}
} // namespace

SCENARIO("NUL path components receive controlled HTTP rejection before room mutation",
         "[database][homeserver][db6][db6-http-admission]")
{
    GIVEN("an authenticated owner of a real SQLite-backed room")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-db6-http-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        auto const cleanup = NulHttpSqliteCleanup{path};
        database.sqlite_path = path.string();
        auto server = merovingian::config::ServerConfig{};
        auto const origin = std::string{"https://db6-origin.example"};
        server.cors.allowed_origins = {origin};
        auto config = merovingian::config::Config{
            server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const owner = merovingian::homeserver::register_local_user(
            runtime.homeserver, "db6_paths",
            std::string(16U, 'r') + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                char{'A'} + char{'!'},
            merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, owner.value, "DB6");
        REQUIRE(session.ok);
        auto const room = merovingian::homeserver::create_room(runtime.homeserver, session.value);
        REQUIRE(room.ok);
        auto const prefix = "/_matrix/client/v3/rooms/" + room.value + "/state/org.example.db6/";
        auto const events_before = runtime.homeserver.database.persistent_store.events.size();
        auto const state_before = runtime.homeserver.database.persistent_store.state.size();
        auto const stream_before = runtime.homeserver.database.next_stream_ordering;

        WHEN("raw and percent-encoded NUL components reach either public dispatcher")
        {
            THEN("every request completes with 400 without leaking a decoding exception or allocating event state")
            {
                auto const targets = std::vector<std::string>{
                    prefix + "%00head",
                    prefix + "mid%00dle",
                    prefix + "tail%00",
                    prefix + std::string{"raw\0key", 7U},
                    "/_matrix/client/v3/rooms/" + room.value + "%00/state/org.example.db6/key",
                    "/_matrix/client/v3/rooms/" + room.value + "/state/org.example.db6%00/key"
                };
                for (auto const& target : targets)
                {
                    for (auto const through_client : {false, true})
                    {
                        auto const request = merovingian::homeserver::LocalHttpRequest{
                            "PUT", target, session.value, "{}", {{"Origin", origin}}};
                        auto response = std::optional<merovingian::homeserver::LocalHttpResponse>{};
                        auto escaped = false;
                        try
                        {
                            response =
                                through_client
                                    ? merovingian::homeserver::handle_client_server_request(runtime, request).response
                                    : merovingian::homeserver::handle_local_http_request(runtime.homeserver, request);
                        }
                        catch (std::invalid_argument const&)
                        {
                            escaped = true;
                        }
                        CHECK_FALSE(escaped);
                        CHECK(response.has_value());
                        if (response.has_value())
                        {
                            CHECK(response->status == 400U);
                            if (through_client)
                            {
                                CHECK(response->body.find("M_INVALID_PARAM") != std::string::npos);
                                CHECK(std::ranges::any_of(response->headers, [&origin](auto const& header) {
                                    return header.first == "Access-Control-Allow-Origin" && header.second == origin;
                                }));
                                CHECK(std::ranges::any_of(response->headers, [](auto const& header) {
                                    return header.first == "Vary" && header.second == "Origin";
                                }));
                            }
                            else
                            {
                                CHECK(response->errcode == "M_INVALID_PARAM");
                            }
                        }
                        CHECK(runtime.homeserver.database.persistent_store.events.size() == events_before);
                        CHECK(runtime.homeserver.database.persistent_store.state.size() == state_before);
                        CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                    }
                }
            }
        }
    }
}

SCENARIO("Path admission decodes once and does not reject NUL data in unrelated query values",
         "[database][homeserver][db6][db6-http-compatibility]")
{
    GIVEN("a running client-server runtime")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        auto started = merovingian::homeserver::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(), security, merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);

        WHEN("a public endpoint carries an encoded NUL only in its query, or a literal percent escape in its path")
        {
            THEN("query data and a once-encoded percent sign do not become invalid path NULs")
            {
                auto const query = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/versions?unused=%00", {}, {}});
                auto const ordinary_query = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/versions?unused=ordinary", {}, {}});
                REQUIRE(ordinary_query.response.status != 400U);
                CHECK(query.response.status == ordinary_query.response.status);
                auto const literal = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/unknown/%2500", {}, {}});
                CHECK(literal.response.status != 400U);
            }
        }
    }
}

SCENARIO("Unrelated query values never become room operation path components",
         "[database][homeserver][integration][db6][db6-query-path]")
{
    GIVEN("an authenticated owner and a real SQLite room with visible events")
    {
        namespace hs = merovingian::homeserver;
        namespace db = merovingian::database;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        auto const path = merovingian::tests::temporary_directory() /
                          ("db6-query-path-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite");
        // Each run owns its SQLite file, so the reopen checks below read only this scenario's data.
        auto const cleanup = NulHttpSqliteCleanup{path};
        database.sqlite_path = path.string();
        auto started = hs::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const owner = hs::register_local_user(
            runtime.homeserver, "db6_paths",
            std::string(16U, 'r') + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                char{'A'} + char{'!'},
            merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = hs::login_local_user_by_id(runtime.homeserver, owner.value, "DB6");
        REQUIRE(session.ok);
        // A real owner and room: every request below is valid, so a failure can only come from the query text.
        auto const room = hs::create_room(runtime.homeserver, session.value);
        REQUIRE(room.ok);
        auto const prefix = "/_matrix/client/v3/rooms/" + room.value;
        // dispatch() fails on any escaped exception and on any status but 200: a query value must never reach a path
        // parser.
        auto const dispatch = [&](std::string method, std::string target, std::string body) {
            auto response = std::optional<hs::LocalHttpResponse>{};
            auto escaped = false;
            try
            {
                response = hs::handle_client_server_request(runtime, {method, target, session.value, body}).response;
            }
            catch (std::invalid_argument const&)
            {
                escaped = true;
            }
            CHECK_FALSE(escaped);
            CHECK(response.has_value());
            if (response.has_value())
            {
                CHECK(response->status == 200U);
            }
            return response;
        };
        auto const seed =
            hs::send_event(runtime.homeserver, session.value, room.value,
                           R"({"type":"org.example.db6","state_key":"read","content":{"value":"read-control"}})");
        REQUIRE(seed.ok);
        // The control read, taken before any query is added, is the body every later read must still equal.
        auto const read_control = dispatch("GET", prefix + "/state/org.example.db6/read", {});
        REQUIRE(read_control.has_value());
        REQUIRE(read_control->status == 200U);
        WHEN("ordinary, encoded NUL and encoded percent query values accompany valid room operations")
        {
            THEN("IDs, transaction scope, state keys, report targets and typing subjects remain the path values")
            {
                auto index = 0U;
                // Cover no query, an ordinary one, an encoded NUL, an encoded percent and a literal NUL byte.
                for (auto const& query : {
                         std::string{},
                         std::string{"?unused=ordinary"},
                         std::string{"?unused=%00"},
                         std::string{"?unused=%2500"},
                         std::string{"?unused=raw\0text", 16U}
                })
                {
                    auto const suffix = std::to_string(index++);
                    auto const txn = "send-" + suffix;
                    auto const message_path = prefix + "/send/m.room.message/" + txn;
                    auto const sent =
                        dispatch("PUT", message_path + query, R"({"msgtype":"m.text","body":"query-control"})");
                    if (sent.has_value() && sent->status == 200U)
                    {
                        // A transaction is scoped by its path ID: the stored record must exist and a replay without the
                        // query must return the same body.
                        auto const cached =
                            db::find_client_txn_event_id(runtime.homeserver.database.persistent_store, owner.value,
                                                         "DB6", room.value, "m.room.message", txn);
                        CHECK(cached.has_value());
                        auto const count = runtime.homeserver.database.persistent_store.events.size();
                        auto const replay =
                            dispatch("PUT", message_path, R"({"msgtype":"m.text","body":"query-control"})");
                        if (replay.has_value())
                        {
                            CHECK((replay->body == sent->body));
                        }
                        CHECK(runtime.homeserver.database.persistent_store.events.size() == count);
                    }
                    // State keys come from the path alone: the written key must be durable after reopening SQLite.
                    auto const state_key = "write-" + suffix;
                    auto const state_path = prefix + "/state/org.example.db6/" + state_key;
                    auto const content = "{\"value\":" + suffix + "}";
                    auto const state_sent = dispatch("PUT", state_path + query, content);
                    if (state_sent.has_value() && state_sent->status == 200U)
                    {
                        auto const state_read = dispatch("GET", state_path, {});
                        if (state_read.has_value())
                        {
                            CHECK((state_read->body == content));
                        }
                        auto reopened = db::open_sqlite_persistent_store(path.string());
                        REQUIRE(reopened.ok);
                        CHECK(std::ranges::any_of(reopened.store.state, [&](auto const& row) {
                            return row.room_id == room.value && row.event_type == "org.example.db6" &&
                                   row.state_key == state_key;
                        }));
                    }
                    auto const read = dispatch("GET", prefix + "/state/org.example.db6/read" + query, {});
                    if (read.has_value())
                    {
                        CHECK((read->body == read_control->body));
                    }
                    // A fresh event per case gives report and redact a target that no earlier case touched.
                    auto const event = hs::send_event(
                        runtime.homeserver, session.value, room.value,
                        R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"report-and-redact"}})");
                    REQUIRE(event.ok);
                    auto const report =
                        dispatch("POST", prefix + "/report/" + event.value + query, R"({"reason":"query-control"})");
                    if (report.has_value() && report->status == 200U)
                    {
                        auto const reports = db::load_audit_events_by_type_prefix(
                            runtime.homeserver.database.persistent_store, "trust_safety.", 1000U);
                        CHECK(std::ranges::any_of(reports, [&](auto const& row) {
                            return row.target == event.value;
                        }));
                    }
                    auto const redact_txn = "redact-" + suffix;
                    auto const redact_path = prefix + "/redact/" + event.value + "/" + redact_txn;
                    auto const redacted = dispatch("PUT", redact_path + query, "{}");
                    if (redacted.has_value() && redacted->status == 200U)
                    {
                        CHECK(db::find_client_txn_event_id(runtime.homeserver.database.persistent_store, owner.value,
                                                           "DB6", room.value, "redact/" + event.value, redact_txn)
                                  .has_value());
                        auto const replay = dispatch("PUT", redact_path, "{}");
                        if (replay.has_value())
                        {
                            CHECK((replay->body == redacted->body));
                        }
                    }
                    // The typing subject is the path user ID, never a value carried by the query.
                    auto const typing_path = prefix + "/typing/" + owner.value;
                    auto const typing = dispatch("PUT", typing_path + query, R"({"typing":true,"timeout":30000})");
                    if (typing.has_value() && typing->status == 200U)
                    {
                        CHECK(std::ranges::any_of(runtime.homeserver.typing_users, [&](auto const& row) {
                            return row.room_id == room.value && row.user_id == owner.value && row.typing;
                        }));
                    }
                    auto const stopped = dispatch("PUT", typing_path, R"({"typing":false})");
                    REQUIRE(stopped.has_value());
                    REQUIRE(stopped->status == 200U);
                }
            }
        }
    }
}

SCENARIO("To-device, user metadata and knock path identities ignore unrelated query text",
         "[database][homeserver][integration][db6][db6-extra-query-path]")
{
    GIVEN("a real SQLite server with authenticated local sender and knocking user")
    {
        namespace hs = merovingian::homeserver;
        namespace db = merovingian::database;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        auto const path = merovingian::tests::temporary_directory() /
                          ("db6-extra-query-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite");
        // Each run owns its SQLite file, so the reopen checks below read only this scenario's data.
        auto const cleanup = NulHttpSqliteCleanup{path};
        database.sqlite_path = path.string();
        auto started = hs::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const owner = hs::register_local_user(
            runtime.homeserver, "db6_extra",
            std::string(16U, 'r') + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                char{'A'} + char{'!'},
            merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = hs::login_local_user_by_id(runtime.homeserver, owner.value, "DB6");
        REQUIRE(session.ok);
        // A second user is the knocker, so the knock is a cross-user action on the owner's room.
        auto const visitor = hs::register_local_user(
            runtime.homeserver, "db6_knocker",
            std::string(16U, 'r') + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                char{'A'} + char{'!'},
            merovingian::tests::registration_token);
        REQUIRE(visitor.ok);
        auto const visitor_session = hs::login_local_user_by_id(runtime.homeserver, visitor.value, "DB6");
        REQUIRE(visitor_session.ok);
        // request() fails on any escaped exception and on any status but 200: a query value must never reach a path
        // parser.
        auto const request = [&](hs::LocalHttpRequest const& req) {
            auto response = std::optional<hs::LocalHttpResponse>{};
            auto escaped = false;
            try
            {
                response = hs::handle_client_server_request(runtime, req).response;
            }
            catch (std::invalid_argument const&)
            {
                escaped = true;
            }
            CHECK_FALSE(escaped);
            CHECK(response.has_value());
            if (response.has_value())
            {
                CHECK(response->status == 200U);
            }
            return response;
        };
        auto const user_path = "/_matrix/client/v3/user/" + owner.value;
        WHEN("valid requests carry ordinary, NUL or literal percent values outside the path")
        {
            THEN("original transaction IDs and metadata keys are durable and the intended room receives the knock")
            {
                auto index = 0U;
                // Cover no query, an ordinary one, an encoded NUL, an encoded percent and a literal NUL byte.
                for (auto const& query : {
                         std::string{},
                         std::string{"?unused=ordinary"},
                         std::string{"?unused=%00"},
                         std::string{"?unused=%2500"},
                         std::string{"?unused=raw\0text", 16U}
                })
                {
                    auto const suffix = std::to_string(index++);
                    auto const txn = "device-" + suffix;
                    auto const device_path = "/_matrix/client/v3/sendToDevice/org.example.db6/" + txn;
                    auto const messages = "{\"messages\":{\"" + owner.value + "\":{\"*\":{\"value\":" + suffix + "}}}}";
                    // To-device transactions are scoped by the path ID: the replay without the query must queue nothing
                    // new.
                    auto const queued_before = runtime.homeserver.database.persistent_store.to_device_messages.size();
                    auto const delivered = request({"PUT", device_path + query, session.value, messages});
                    if (delivered.has_value() && delivered->status == 200U)
                    {
                        CHECK(db::find_client_txn_event_id(runtime.homeserver.database.persistent_store, owner.value,
                                                           "DB6", "", "org.example.db6", txn)
                                  .has_value());
                        CHECK(runtime.homeserver.database.persistent_store.to_device_messages.size() > queued_before);
                        auto const queued_after =
                            runtime.homeserver.database.persistent_store.to_device_messages.size();
                        auto const replay = request({"PUT", device_path, session.value, messages});
                        CHECK(replay.has_value());
                        CHECK(runtime.homeserver.database.persistent_store.to_device_messages.size() == queued_after);
                    }
                    // Account data is keyed by the path type; the stored row must survive reopening SQLite.
                    auto const type = "org.example.db6." + suffix;
                    auto const account_path = user_path + "/account_data/" + type;
                    auto const content = "{\"value\":" + suffix + "}";
                    auto const stored = request({"PUT", account_path + query, session.value, content});
                    if (stored.has_value() && stored->status == 200U)
                    {
                        auto const read = request({"GET", account_path, session.value, {}});
                        if (read.has_value())
                        {
                            CHECK((read->body == content));
                        }
                        auto const query_read = request({"GET", account_path + query, session.value, {}});
                        if (query_read.has_value())
                        {
                            CHECK((query_read->body == content));
                        }
                        auto reopened = db::open_sqlite_persistent_store(path.string());
                        REQUIRE(reopened.ok);
                        CHECK(std::ranges::any_of(reopened.store.account_data, [&](auto const& row) {
                            return row.user_id == owner.value && row.room_id.empty() && row.event_type == type &&
                                   row.content_json == content;
                        }));
                    }
                    // A fresh room per case, so each tag and knock targets a room no earlier case touched.
                    auto const room = hs::create_room(runtime.homeserver, session.value);
                    REQUIRE(room.ok);
                    auto const tags_path = user_path + "/rooms/" + room.value + "/tags";
                    auto const tag = "org.example.db6." + suffix;
                    auto const tagged = request({"PUT", tags_path + "/" + tag + query, session.value, "{}"});
                    if (tagged.has_value() && tagged->status == 200U)
                    {
                        auto const read = request({"GET", tags_path, session.value, {}});
                        if (read.has_value())
                        {
                            CHECK(read->body.find("\"" + tag + "\"") != std::string::npos);
                        }
                        auto const query_read = request({"GET", tags_path + query, session.value, {}});
                        if (read.has_value() && query_read.has_value())
                        {
                            CHECK((read->body == query_read->body));
                        }
                        auto const deleted = request({"DELETE", tags_path + "/" + tag + query, session.value, {}});
                        CHECK(deleted.has_value());
                        auto const after = request({"GET", tags_path, session.value, {}});
                        if (after.has_value())
                        {
                            CHECK((after->body == "{\"tags\":{}}"));
                        }
                    }
                    // Knocking needs a knock join rule, so the room is switched to it first.
                    auto const rule = hs::send_event(
                        runtime.homeserver, session.value, room.value,
                        R"({"type":"m.room.join_rules","state_key":"","content":{"join_rule":"knock"}})");
                    REQUIRE(rule.ok);
                    auto const knock = request(
                        {"POST", "/_matrix/client/v3/knock/" + room.value + query, visitor_session.value, "{}"});
                    if (knock.has_value() && knock->status == 200U)
                    {
                        CHECK(std::ranges::any_of(runtime.homeserver.database.persistent_store.memberships,
                                                  [&](auto const& row) {
                                                      return row.room_id == room.value &&
                                                             row.user_id == visitor.value && row.membership == "knock";
                                                  }));
                        auto reopened = db::open_sqlite_persistent_store(path.string());
                        REQUIRE(reopened.ok);
                        CHECK(std::ranges::any_of(reopened.store.memberships, [&](auto const& row) {
                            return row.room_id == room.value && row.user_id == visitor.value &&
                                   row.membership == "knock";
                        }));
                    }
                }
            }
        }
    }
}

SCENARIO("Recognized join-server query parameters reject NUL without escaping either dispatcher",
         "[database][homeserver][db6][db6-join-query]")
{
    GIVEN("an authenticated owner in a real in-process room")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        auto const path = merovingian::tests::temporary_directory() /
                          ("db6-join-hints-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite");
        auto const cleanup = NulHttpSqliteCleanup{path};
        database.sqlite_path = path.string();
        auto started = merovingian::homeserver::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const owner = merovingian::homeserver::register_local_user(
            runtime.homeserver, "db6_query",
            std::string(16U, 'r') + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                char{'A'} + char{'!'},
            merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, owner.value, "DB6");
        REQUIRE(session.ok);
        // The owner is already in the room, so a join without a bad hint succeeds; only the hint can change the
        // outcome.
        auto const room = merovingian::homeserver::create_room(runtime.homeserver, session.value);
        REQUIRE(room.ok);
        auto const prefix = "/_matrix/client/v3/join/" + room.value + "?";

        WHEN("a recognized server hint contains literal or once-decoded NUL")
        {
            THEN("it returns a controlled invalid-parameter response without event or state allocation")
            {
                // Run the same request through both dispatchers, the client-server one and the local router.
                for (auto const through_client : {true, false})
                {
                    auto const route = through_client ? prefix : "/_matrix/client/v3/rooms/" + room.value + "/join?";
                    auto const control = through_client ? merovingian::homeserver::handle_client_server_request(
                                                              runtime, {"POST", route, session.value, "{}"})
                                                              .response
                                                        : merovingian::homeserver::handle_local_http_request(
                                                              runtime.homeserver, {"POST", route, session.value, "{}"});
                    // The control join proves the route works before any NUL is added.
                    REQUIRE(control.status == 200U);
                    for (auto const& parameter : {std::string{"via="}, std::string{"server_name="}})
                    {
                        for (auto const& value : {
                                 std::string{"%00head"},
                                 std::string{"mid%00dle"},
                                 std::string{"tail%00"},
                                 std::string{"raw\0host", 8U}
                        })
                        {
                            // Snapshot the in-memory and durable stores first: a refused hint must allocate no event,
                            // state or stream position.
                            auto const events_before = runtime.homeserver.database.persistent_store.events.size();
                            auto const state_before = runtime.homeserver.database.persistent_store.state.size();
                            auto const stream_before = runtime.homeserver.database.next_stream_ordering;
                            auto const snapshot_before =
                                nul_business_snapshot(runtime.homeserver.database.persistent_store);
                            auto reopened_before = merovingian::database::open_sqlite_persistent_store(path.string());
                            REQUIRE(reopened_before.ok);
                            auto const durable_before = nul_business_snapshot(reopened_before.store);
                            auto response = std::optional<merovingian::homeserver::LocalHttpResponse>{};
                            auto escaped = false;
                            try
                            {
                                auto const request = merovingian::homeserver::LocalHttpRequest{
                                    "POST", route + parameter + value, session.value, "{}"};
                                response = through_client
                                               ? merovingian::homeserver::handle_client_server_request(runtime, request)
                                                     .response
                                               : merovingian::homeserver::handle_local_http_request(runtime.homeserver,
                                                                                                    request);
                            }
                            // An escaping invalid_argument would mean the NUL reached a parser unchecked instead of
                            // being refused.
                            catch (std::invalid_argument const&)
                            {
                                escaped = true;
                            }
                            CHECK_FALSE(escaped);
                            CHECK(response.has_value());
                            if (response.has_value())
                            {
                                // The spec's error for a bad parameter is 400 M_INVALID_PARAM, never a 500 or a silent
                                // success.
                                CHECK(response->status == 400U);
                                CHECK(response->body.find("M_INVALID_PARAM") != std::string::npos);
                            }
                            CHECK(runtime.homeserver.database.persistent_store.events.size() == events_before);
                            CHECK(runtime.homeserver.database.persistent_store.state.size() == state_before);
                            CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                            CHECK((nul_business_snapshot(runtime.homeserver.database.persistent_store) ==
                                   snapshot_before));
                            // Reopen SQLite to prove nothing was written durably either.
                            auto reopened_after = merovingian::database::open_sqlite_persistent_store(path.string());
                            REQUIRE(reopened_after.ok);
                            CHECK((nul_business_snapshot(reopened_after.store) == durable_before));
                        }
                    }
                    // Hints that are merely unusual (ordinary, a literal percent sequence, an unrelated key) must still
                    // be accepted.
                    for (auto const& query : {std::string{"via=ordinary.example"},
                                              std::string{"via=percent%2500.example"}, std::string{"unused=%00"}})
                    {
                        auto const request =
                            merovingian::homeserver::LocalHttpRequest{"POST", route + query, session.value, "{}"};
                        auto const response =
                            through_client
                                ? merovingian::homeserver::handle_client_server_request(runtime, request).response
                                : merovingian::homeserver::handle_local_http_request(runtime.homeserver, request);
                        CHECK(response.status == 200U);
                    }
                }
            }
        }
    }
}
