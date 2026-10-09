// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <sqlite3.h>

namespace
{

struct SqliteCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        if (connection != nullptr)
        {
            std::ignore = sqlite3_close(connection);
        }
    }
};

class SqliteConnection final
{
public:
    explicit SqliteConnection(std::filesystem::path const& path)
    {
        auto* raw_connection = static_cast<sqlite3*>(nullptr);
        auto const status = sqlite3_open(path.string().c_str(), &raw_connection);
        connection_.reset(raw_connection);
        REQUIRE(status == SQLITE_OK);
        REQUIRE(connection_ != nullptr);
    }

    SqliteConnection(SqliteConnection const&) = delete;
    auto operator=(SqliteConnection const&) -> SqliteConnection& = delete;
    SqliteConnection(SqliteConnection&&) = delete;
    auto operator=(SqliteConnection&&) -> SqliteConnection& = delete;

    [[nodiscard]] auto execute(std::string_view sql) const -> bool
    {
        auto const statement = std::string{sql};
        return sqlite3_exec(connection_.get(), statement.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    [[nodiscard]] auto native_handle() const noexcept -> sqlite3&
    {
        return *connection_;
    }

private:
    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
};

// The runtime owns the discovery network, so the test shares the counter to keep reading it.
using SharedCallCounter = std::shared_ptr<std::atomic<std::uint32_t>>; // SHARED_PTR: reviewed — counter read by test

class CountingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit CountingDiscoveryNetwork(SharedCallCounter calls)
        : calls_{std::move(calls)}
    {
    }

    [[nodiscard]] auto fetch_well_known(std::string_view server_name, std::uint32_t timeout)
        -> merovingian::federation::WellKnownServerResult override
    {
        calls_->fetch_add(1U);
        return delegate_->fetch_well_known(server_name, timeout);
    }

    [[nodiscard]] auto lookup_srv(std::string_view service_name)
        -> std::vector<merovingian::federation::SrvRecord> override
    {
        calls_->fetch_add(1U);
        return delegate_->lookup_srv(service_name);
    }

    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t port)
        -> merovingian::federation::ResolvedAddressSet override
    {
        calls_->fetch_add(1U);
        return delegate_->lookup_addresses(host, port);
    }

private:
    SharedCallCounter calls_;
    std::unique_ptr<merovingian::federation::ServerDiscoveryNetwork> delegate_{
        merovingian::federation::make_system_server_discovery_network()};
};

class TemporarySqliteDatabase final
{
public:
    TemporarySqliteDatabase()
    {
        auto const ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() /
                ("merovingian-security-audit-directory-" + std::to_string(ticks) + ".sqlite3");
        remove_files();
    }

    TemporarySqliteDatabase(TemporarySqliteDatabase const&) = delete;
    auto operator=(TemporarySqliteDatabase const&) -> TemporarySqliteDatabase& = delete;
    TemporarySqliteDatabase(TemporarySqliteDatabase&&) = delete;
    auto operator=(TemporarySqliteDatabase&&) -> TemporarySqliteDatabase& = delete;

    ~TemporarySqliteDatabase()
    {
        remove_files();
    }

    [[nodiscard]] auto path() const noexcept -> std::filesystem::path const&
    {
        return path_;
    }

private:
    auto remove_files() const noexcept -> void
    {
        auto error = std::error_code{};
        std::filesystem::remove(path_, error);
        error.clear();
        std::filesystem::remove(path_.string() + "-wal", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-shm", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-journal", error);
    }

    std::filesystem::path path_{};
};

[[nodiscard]] auto directory_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);

    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            std::move(database),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto parse_response(std::string const& body) -> merovingian::canonicaljson::Object
{
    return merovingian::tests::parse_object(body);
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view token,
                               std::string_view body) -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", std::string{token}, std::string{body}});
    REQUIRE(response.response.status == 200U);
    auto const parsed = parse_response(response.response.body);
    auto const* room_id = merovingian::tests::string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto visibility(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view token,
                              std::string_view room_id) -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/directory/list/room/" + std::string{room_id}, std::string{token}, {}});
    REQUIRE(response.response.status == 200U);
    auto const parsed = parse_response(response.response.body);
    auto const* value = merovingian::tests::string_member(parsed, "visibility");
    REQUIRE(value != nullptr);
    return *value;
}

[[nodiscard]] auto public_room_ids(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view token)
    -> std::vector<std::string>
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/publicRooms", std::string{token}, {}});
    REQUIRE(response.response.status == 200U);
    auto const parsed = parse_response(response.response.body);
    auto const* chunk = merovingian::tests::object_member_as_array(parsed, "chunk");
    REQUIRE(chunk != nullptr);

    auto result = std::vector<std::string>{};
    for (auto const& item : *chunk)
    {
        auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&item.storage());
        REQUIRE(entry != nullptr);
        auto const* room_id = merovingian::tests::string_member(*entry, "room_id");
        REQUIRE(room_id != nullptr);
        result.push_back(*room_id);
    }
    return result;
}

[[nodiscard]] auto join_rule(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view room_id)
    -> std::string
{
    auto const& store = runtime.homeserver.database.persistent_store;
    auto const state = std::ranges::find_if(store.state, [room_id](auto const& candidate) {
        return candidate.room_id == room_id && candidate.event_type == "m.room.join_rules" &&
               candidate.state_key.empty();
    });
    REQUIRE(state != store.state.end());
    auto const event = std::ranges::find_if(store.events, [&state](auto const& candidate) {
        return candidate.event_id == state->event_id;
    });
    REQUIRE(event != store.events.end());
    auto const body = parse_response(event->json);
    auto const* content = merovingian::tests::object_member_as_object(body, "content");
    REQUIRE(content != nullptr);
    auto const* value = merovingian::tests::string_member(*content, "join_rule");
    REQUIRE(value != nullptr);
    return *value;
}

[[nodiscard]] auto bootstrap_sqlite_to_version(sqlite3& connection, std::uint32_t target_version) -> bool
{
    auto const plan = merovingian::database::migration_plan_between(0U, target_version);
    for (auto const& step : plan.steps)
    {
        for (auto const& statement : step.statements)
        {
            auto const sql = std::string{statement.sql};
            if (sqlite3_exec(&connection, sql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
            {
                return false;
            }
        }
        // The C API returns ownership through an out-parameter; wrap it
        // immediately. Even compiled migration ledger values are bound.
        // Bound strings outlive the statement (destroyed in reverse order),
        // so SQLite may borrow them without a destructor callback.
        auto const version = std::to_string(step.version);
        auto const direction = std::string{merovingian::database::migration_direction_name(step.direction)};
        auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
        auto const prepared = sqlite3_prepare_v2(&connection, "INSERT INTO schema_migrations VALUES (?1, ?2, ?3)", -1,
                                                 &raw_statement, nullptr);
        auto statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>{raw_statement, &sqlite3_finalize};
        if (prepared != SQLITE_OK || statement == nullptr)
        {
            return false;
        }
        if (sqlite3_bind_text(statement.get(), 1, version.c_str(), static_cast<int>(version.size()), nullptr) !=
                SQLITE_OK ||
            sqlite3_bind_text(statement.get(), 2, step.name.c_str(), static_cast<int>(step.name.size()), nullptr) !=
                SQLITE_OK ||
            sqlite3_bind_text(statement.get(), 3, direction.c_str(), static_cast<int>(direction.size()), nullptr) !=
                SQLITE_OK ||
            sqlite3_step(statement.get()) != SQLITE_DONE)
        {
            return false;
        }
    }
    return true;
}
} // namespace

// Matrix v1.19: POST /_matrix/client/v3/publicRooms requires authentication;
// GET /_matrix/client/v3/publicRooms does not.
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3publicrooms
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3publicrooms
SCENARIO("public room listing enforces POST authentication while keeping GET public",
         "[security_audit_directory][integration]")
{
    GIVEN("a running SQLite-backed homeserver and a registered user")
    {
        auto const temporary_database = TemporarySqliteDatabase{};
        auto const config = directory_config(temporary_database.path());
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const discovery_calls = std::make_shared<std::atomic<std::uint32_t>>(0U);
        runtime.homeserver.discovery_network = std::make_unique<CountingDiscoveryNetwork>(discovery_calls);
        runtime.homeserver.cached_discovery = std::make_unique<merovingian::federation::CachedServerDiscovery>(
            *runtime.homeserver.discovery_network, 60000U, []() -> std::uint64_t {
                return 0U;
            });
        auto const registered = merovingian::homeserver::register_local_user(
            runtime.homeserver, "directory_auth", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(registered.ok);
        auto const login =
            merovingian::homeserver::login_local_user_by_id(runtime.homeserver, registered.value, "DIRECTORY_AUTH");
        REQUIRE(login.ok);

        WHEN("local and remote POST requests are unauthenticated, while GET is sent without a token")
        {
            auto const missing_post = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/publicRooms", {}, "{}"});
            auto const invalid_post = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/publicRooms", "not-a-session-token", "{}"});
            auto const remote_missing_post = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/publicRooms?server=127.0.0.1:8448", {}, "{}"});
            auto const remote_invalid_post = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/publicRooms?server=127.0.0.1:8448", "not-a-session-token", "{}"});
            auto const public_get = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/publicRooms", {}, {}});

            THEN("every POST rejects before remote discovery and GET remains available without a token")
            {
                REQUIRE(missing_post.response.status == 401U);
                auto const missing_body = parse_response(missing_post.response.body);
                auto const* missing_code = merovingian::tests::string_member(missing_body, "errcode");
                REQUIRE(missing_code != nullptr);
                CHECK(*missing_code == "M_MISSING_TOKEN");

                REQUIRE(invalid_post.response.status == 401U);
                auto const invalid_body = parse_response(invalid_post.response.body);
                auto const* invalid_code = merovingian::tests::string_member(invalid_body, "errcode");
                REQUIRE(invalid_code != nullptr);
                CHECK(*invalid_code == "M_UNKNOWN_TOKEN");

                REQUIRE(remote_missing_post.response.status == 401U);
                REQUIRE(remote_invalid_post.response.status == 401U);
                REQUIRE(discovery_calls->load() == 0U);
                REQUIRE(public_get.response.status == 200U);
            }
        }

        WHEN("POST is sent with a valid access token")
        {
            auto const authenticated_post = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/publicRooms", login.value, "{}"});

            THEN("the authenticated client receives the directory response")
            {
                REQUIRE(authenticated_post.response.status == 200U);
                auto const parsed = parse_response(authenticated_post.response.body);
                CHECK(merovingian::tests::object_member_as_array(parsed, "chunk") != nullptr);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3directorylistroomroomid
// A room is listed only after it is made public in the room directory. The
// visibility choice survives a homeserver restart independently of join rule.
SCENARIO("directory visibility and public room listings survive SQLite restart",
         "[security_audit_directory][integration][sqlite]")
{
    GIVEN("a SQLite-backed homeserver with default-private and public rooms")
    {
        auto const temporary_database = TemporarySqliteDatabase{};
        auto const config = directory_config(temporary_database.path());
        auto token = std::string{};
        auto default_private_room = std::string{};
        auto created_public_room = std::string{};
        auto publishable_room = std::string{};

        WHEN("visibility changes from private to public and back across runtime restarts")
        {
            auto public_visibility = std::string{};
            auto public_listing = std::vector<std::string>{};
            auto final_private_visibility = std::string{};
            auto final_listing = std::vector<std::string>{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto const registered = merovingian::homeserver::register_local_user(
                    started.runtime.homeserver, "directory_restart", "CorrectHorse7!",
                    merovingian::tests::registration_token);
                REQUIRE(registered.ok);
                auto const login = merovingian::homeserver::login_local_user_by_id(
                    started.runtime.homeserver, registered.value, "DIRECTORY_RESTART");
                REQUIRE(login.ok);
                token = login.value;

                default_private_room = create_room(started.runtime, token, "{}");
                created_public_room =
                    create_room(started.runtime, token, R"({"visibility":"public","preset":"private_chat"})");
                publishable_room = create_room(started.runtime, token, R"({"preset":"public_chat"})");

                REQUIRE(visibility(started.runtime, token, default_private_room) == "private");
                REQUIRE(visibility(started.runtime, token, created_public_room) == "public");
                REQUIRE(join_rule(started.runtime, created_public_room) == "invite");
                REQUIRE(visibility(started.runtime, token, publishable_room) == "private");

                auto const publish = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/" + publishable_room, token,
                                      R"({"visibility":"public"})"});
                REQUIRE(publish.response.status == 200U);
            }

            {
                auto restarted = merovingian::homeserver::start_client_server(config);
                REQUIRE(restarted.started);
                public_visibility = visibility(restarted.runtime, token, publishable_room);
                public_listing = public_room_ids(restarted.runtime, token);
                REQUIRE(join_rule(restarted.runtime, created_public_room) == "invite");

                auto const unpublish = merovingian::homeserver::handle_client_server_request(
                    restarted.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/" + publishable_room, token,
                                        R"({"visibility":"private"})"});
                REQUIRE(unpublish.response.status == 200U);
            }

            auto restarted_again = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted_again.started);
            final_private_visibility = visibility(restarted_again.runtime, token, publishable_room);
            final_listing = public_room_ids(restarted_again.runtime, token);

            THEN("default visibility stays private and public/private updates persist")
            {
                CHECK(public_visibility == "public");
                CHECK(std::ranges::find(public_listing, created_public_room) != public_listing.end());
                CHECK(std::ranges::find(public_listing, publishable_room) != public_listing.end());
                CHECK(std::ranges::find(public_listing, default_private_room) == public_listing.end());
                CHECK(visibility(restarted_again.runtime, token, default_private_room) == "private");
                CHECK(visibility(restarted_again.runtime, token, created_public_room) == "public");
                CHECK(join_rule(restarted_again.runtime, created_public_room) == "invite");
                CHECK(final_private_visibility == "private");
                CHECK(std::ranges::find(final_listing, publishable_room) == final_listing.end());
                CHECK(std::ranges::find(final_listing, created_public_room) != final_listing.end());
            }
        }
    }
}

SCENARIO("failed directory visibility writes do not publish the room in memory or after restart",
         "[security_audit_directory][integration][sqlite]")
{
    GIVEN("a SQLite-backed homeserver and a room that starts private")
    {
        auto const temporary_database = TemporarySqliteDatabase{};
        auto const config = directory_config(temporary_database.path());
        struct Observation final
        {
            std::string token{};
            std::string room_id{};
            std::uint16_t status{0U};
            std::string visibility{};
            bool persisted_public{false};
            bool listed{false};
        };
        auto observation = Observation{};

        WHEN("SQLite aborts the persisted visibility update")
        {
            observation = [&] {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto& runtime = started.runtime;
                auto const registered = merovingian::homeserver::register_local_user(
                    runtime.homeserver, "directory_failure", "CorrectHorse7!", merovingian::tests::registration_token);
                REQUIRE(registered.ok);
                auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, registered.value,
                                                                                   "DIRECTORY_FAILURE");
                REQUIRE(login.ok);
                auto const room_id = create_room(runtime, login.value, "{}");
                REQUIRE(visibility(runtime, login.value, room_id) == "private");

                auto sqlite = SqliteConnection{temporary_database.path()};
                REQUIRE(sqlite.execute(
                    "CREATE TRIGGER reject_directory_visibility BEFORE UPDATE OF directory_public ON rooms "
                    "BEGIN SELECT RAISE(ABORT, 'test directory write failure'); END"));
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/directory/list/room/" + room_id, login.value,
                              R"({"visibility":"public"})"});
                auto const stored_room = std::ranges::find_if(runtime.homeserver.database.persistent_store.rooms,
                                                              [&room_id](auto const& candidate) {
                                                                  return candidate.room_id == room_id;
                                                              });
                REQUIRE(stored_room != runtime.homeserver.database.persistent_store.rooms.end());
                auto const listing = public_room_ids(runtime, login.value);
                return Observation{login.value,
                                   room_id,
                                   response.response.status,
                                   visibility(runtime, login.value, room_id),
                                   stored_room->directory_public,
                                   std::ranges::find(listing, room_id) != listing.end()};
            }();

            THEN("the server reports failure and keeps the room private in memory and SQLite")
            {
                REQUIRE(observation.status == 500U);
                CHECK(observation.visibility == "private");
                CHECK_FALSE(observation.persisted_public);
                CHECK_FALSE(observation.listed);

                auto restarted = merovingian::homeserver::start_client_server(config);
                REQUIRE(restarted.started);
                CHECK(visibility(restarted.runtime, observation.token, observation.room_id) == "private");
                auto const listing = public_room_ids(restarted.runtime, observation.token);
                CHECK(std::ranges::find(listing, observation.room_id) == listing.end());
                auto const reloaded_room =
                    std::ranges::find_if(restarted.runtime.homeserver.database.persistent_store.rooms,
                                         [&observation](auto const& candidate) {
                                             return candidate.room_id == observation.room_id;
                                         });
                REQUIRE(reloaded_room != restarted.runtime.homeserver.database.persistent_store.rooms.end());
                CHECK_FALSE(reloaded_room->directory_public);
            }
        }
    }
}

SCENARIO("schema version 17 rooms migrate to private directory visibility",
         "[security_audit_directory][integration][sqlite][migration]")
{
    GIVEN("a SQLite database at schema version 17 containing a legacy room")
    {
        auto const temporary_database = TemporarySqliteDatabase{};
        auto const legacy_room_id = std::string{"!legacy-directory:example.org"};
        {
            auto sqlite = SqliteConnection{temporary_database.path()};
            REQUIRE(bootstrap_sqlite_to_version(sqlite.native_handle(), 17U));
            REQUIRE(sqlite.execute("INSERT INTO rooms (room_id, creator_user_id) "
                                   "VALUES ('!legacy-directory:example.org', '@legacy:example.org')"));
        }

        WHEN("homeserver startup applies the next additive migration")
        {
            auto started = merovingian::homeserver::start_client_server(directory_config(temporary_database.path()));

            THEN("the legacy room remains private and is absent from the public directory")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.homeserver.database.schema_version == 21U);
                auto const persisted_room = std::ranges::find_if(
                    started.runtime.homeserver.database.persistent_store.rooms, [&legacy_room_id](auto const& room) {
                        return room.room_id == legacy_room_id;
                    });
                REQUIRE(persisted_room != started.runtime.homeserver.database.persistent_store.rooms.end());
                CHECK_FALSE(persisted_room->directory_public);
                auto const local_room = std::ranges::find_if(started.runtime.homeserver.database.rooms,
                                                             [&legacy_room_id](auto const& room) {
                                                                 return room.room_id == legacy_room_id;
                                                             });
                REQUIRE(local_room != started.runtime.homeserver.database.rooms.end());
                CHECK_FALSE(local_room->directory_public);
                auto const listing = public_room_ids(started.runtime, {});
                CHECK(std::ranges::find(listing, legacy_room_id) == listing.end());
            }
        }
    }
}
