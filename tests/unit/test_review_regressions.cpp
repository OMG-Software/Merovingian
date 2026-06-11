// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <sqlite3.h>

namespace
{

static_assert(std::is_move_constructible_v<merovingian::homeserver::HomeserverRuntime>);
static_assert(std::is_move_assignable_v<merovingian::homeserver::HomeserverRuntime>);
static_assert(std::is_move_constructible_v<merovingian::homeserver::ClientServerRuntime>);
static_assert(std::is_move_assignable_v<merovingian::homeserver::ClientServerRuntime>);

class TestSqliteConnection final
{
public:
    explicit TestSqliteConnection(std::filesystem::path const& path)
    {
        static_cast<void>(sqlite3_open(path.string().c_str(), &connection_));
    }

    TestSqliteConnection(TestSqliteConnection const& other) = delete;
    auto operator=(TestSqliteConnection const& other) -> TestSqliteConnection& = delete;
    TestSqliteConnection(TestSqliteConnection&& other) noexcept = delete;
    auto operator=(TestSqliteConnection&& other) noexcept -> TestSqliteConnection& = delete;

    ~TestSqliteConnection()
    {
        sqlite3_close(connection_);
    }

    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        auto* error = static_cast<char*>(nullptr);
        auto const ok = sqlite3_exec(connection_, sql.c_str(), nullptr, nullptr, &error) == SQLITE_OK;
        sqlite3_free(error);
        return ok;
    }

private:
    sqlite3* connection_{nullptr};
};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto token_required_registration_config(std::filesystem::path const& token_file)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    security.registration.require_token = true;
    security.registration.token_file = token_file.string();
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_secret_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-secret-" + suffix + "-" + std::to_string(now));
}

[[nodiscard]] auto unique_sqlite_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-review-" + suffix + "-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto extract_json_string(std::string const& body, std::string_view key) -> std::string
{
    auto const marker = std::string{"\""} + std::string{key} + "\":\"";
    auto const start = body.find(marker);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + marker.size();
    auto const value_end = body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_start, value_end - value_start);
}

[[nodiscard]] auto remote_runtime(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 4102444800000U,
                          merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto x_matrix_authorization(std::string_view origin, std::string_view key_id, std::string_view key_seed,
                                          std::string_view destination, std::string_view method,
                                          std::string_view target, std::string_view body) -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return std::string{"X-Matrix origin=\""} + std::string{origin} + "\",key=\"" + std::string{key_id} + "\",sig=\"" +
           signature + "\",destination=\"" + std::string{destination} + "\"";
}

class BlockingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit BlockingDiscoveryNetwork(std::chrono::milliseconds delay)
        : delay_{delay}
    {
    }

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        {
            auto lock = std::scoped_lock<std::mutex>{mutex_};
            started_ = true;
        }
        started_cv_.notify_all();
        std::this_thread::sleep_for(delay_);
        return {false, false, {}, "not configured"};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        return {false, {}, "address lookup blocked for regression test"};
    }

    auto wait_until_started() -> void
    {
        auto lock = std::unique_lock<std::mutex>{mutex_};
        auto const started = started_cv_.wait_for(lock, std::chrono::seconds{2}, [this] {
            return started_;
        });
        REQUIRE(started);
    }

private:
    std::chrono::milliseconds delay_{};
    std::mutex mutex_{};
    std::condition_variable started_cv_{};
    bool started_{false};
};

} // namespace

SCENARIO("Admin health remains admin-only after router split", "[homeserver][security][review]")
{
    GIVEN("a runtime with an admin user and a regular user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin_user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        auto const admin_login =
            merovingian::homeserver::login_local_user(runtime, admin_user.value, "CorrectHorse7!", "ADMIN1");
        auto const normal_user = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse8!",
                                                                              merovingian::tests::registration_token);
        auto const normal_login =
            merovingian::homeserver::login_local_user(runtime, normal_user.value, "CorrectHorse8!", "USER1");
        REQUIRE(admin_login.ok);
        REQUIRE(normal_login.ok);

        WHEN("both users request admin health")
        {
            auto const admin_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", admin_login.value, {}});
            auto const normal_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", normal_login.value, {}});

            THEN("only the admin session can read operational health")
            {
                REQUIRE(admin_response.status == 200U);
                REQUIRE(normal_response.status == 401U);
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_admin_user(runtime, normal_login.value).has_value());
            }
        }
    }
}

SCENARIO("Runtime membership projection ignores non-joined invite and knock updates",
         "[homeserver][review][membership]")
{
    GIVEN("a local room whose joined-members projection already contains the same user")
    {
        auto database = merovingian::homeserver::LocalDatabase{};
        database.rooms.push_back({"!room:example.org", "@alice:example.org", {"@bob:example.org"}, {}});

        WHEN("invite and knock membership updates are applied to the runtime projection")
        {
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "invite");
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "knock");

            THEN("the joined-members projection is unchanged")
            {
                REQUIRE(database.rooms.size() == 1U);
                REQUIRE(database.rooms.front().members.size() == 1U);
                REQUIRE(database.rooms.front().members.front() == "@bob:example.org");
            }
        }
    }
}

SCENARIO("Public registration enforces configured token policy and never bootstraps admin",
         "[homeserver][security][auth][review]")
{
    GIVEN("a runtime with token-protected registration")
    {
        auto const token_file = unique_secret_path("registration-token");
        {
            auto output = std::ofstream{token_file};
            output << "register-alpha-token\n";
        }
        auto started = merovingian::homeserver::start_client_server(token_required_registration_config(token_file));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("clients register without, with invalid, and with valid registration tokens")
        {
            auto const missing_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});
            auto const invalid_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"wrong"},"username":"alice","password":"CorrectHorse7!"})"});
            auto const accepted = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"register-alpha-token"},"username":"alice","password":"CorrectHorse7!"})"});

            THEN("only the valid token creates a non-admin user")
            {
                // No auth field yields the UI-auth challenge (401); a present
                // but invalid token is rejected outright (403). All three
                // dispatches should complete (not request a long-poll wait).
                REQUIRE(missing_token.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(missing_token.response.status == 401U);
                REQUIRE(invalid_token.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(invalid_token.response.status == 403U);
                REQUIRE(accepted.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(accepted.response.status == 200U);
                REQUIRE_FALSE(runtime.homeserver.database.users.empty());
                REQUIRE_FALSE(runtime.homeserver.database.users.front().admin);
            }
        }

        std::filesystem::remove(token_file);
    }
}

SCENARIO("Federation dispatch exposes only federation routes", "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime served through federation dispatch mode")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        WHEN("admin, client, and federation key routes are requested")
        {
            auto const admin = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const client_register = merovingian::homeserver::dispatch_local_http_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_pipe("alice", "CorrectHorse7!")},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const keys = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("non-federation surfaces are hidden and federation keys remain reachable")
            {
                REQUIRE(admin.status == 404U);
                REQUIRE(client_register.status == 404U);
                REQUIRE(keys.status == 200U);
                REQUIRE(keys.body.find("\"verify_keys\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation auth failures do not surface as client-style 401s", "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime handling a federation request without valid auth")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the inbound federation profile route is requested without an X-Matrix signature")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime, {"GET",
                          "/_matrix/federation/v1/query/profile?user_id=%40jcadmin%3Apong.ping.me.uk&field=displayname",
                          {},
                          {}});

            THEN("the failure is reported as a server-side federation error instead of 401")
            {
                // Synapse can propagate 401 from a federation exchange back to a
                // client-server request, which Element interprets as an invalid
                // access token and turns into an automatic logout.
                REQUIRE(response.status == 502U);
                REQUIRE(response.body == "malformed federation authorization");
            }
        }
    }
}

SCENARIO("Inbound federation query/profile answers existing local users even without a stored profile row",
         "[homeserver][federation][query-profile][review][regression]")
{
    GIVEN("a started client-server runtime with a registered local user and a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);

        std::erase_if(runtime.homeserver.database.persistent_store.profiles,
                      [](merovingian::database::PersistentProfile const& profile) {
                          return profile.user_id == "@alice:example.org";
                      });

        auto constexpr remote_origin = "matrix.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "query-profile-review-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));

        WHEN("the remote homeserver sends a signed federation query/profile request")
        {
            auto const target = std::string{"/_matrix/federation/v1/query/profile?user_id=%40alice%3Aexample.org"};
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver, {"GET",
                                     target,
                                     x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed,
                                                            "example.org", "GET", target, ""),
                                     {}});

            THEN("the route returns an empty but spec-shaped profile object instead of failing upstream")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("displayname":"")") != std::string::npos);
                REQUIRE(response.body.find(R"("avatar_url":"")") != std::string::npos);
            }
        }
    }
}

SCENARIO("A blocking remote join does not serialize unrelated client requests",
         "[homeserver][locking][review][regression]")
{
    GIVEN("a started client-server runtime with a remote join blocked in discovery")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);
        auto const login_response = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_response.response.status == 200U);
        auto const access_token = extract_json_string(login_response.response.body, "access_token");

        auto discovery = std::make_unique<BlockingDiscoveryNetwork>(std::chrono::milliseconds{250});
        auto* discovery_ptr = discovery.get();
        runtime.homeserver.discovery_network = std::move(discovery);

        auto join_response = merovingian::homeserver::LocalHttpResponse{};
        auto join_thread = std::thread{[&] {
            join_response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!blocked:remote.example.org/join", access_token, {}},
                merovingian::homeserver::HttpDispatchMode::client_server);
        }};

        discovery_ptr->wait_until_started();

        WHEN("another client request arrives while discovery is still blocked")
        {
            auto const before = std::chrono::steady_clock::now();
            auto const versions = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}},
                merovingian::homeserver::HttpDispatchMode::client_server);
            auto const elapsed = std::chrono::steady_clock::now() - before;

            join_thread.join();

            THEN("the unrelated request completes without waiting for the remote join to finish")
            {
                REQUIRE(versions.status == 200U);
                REQUIRE(elapsed < std::chrono::milliseconds{150});
                REQUIRE(join_response.status == 502U);
                REQUIRE(join_response.body.find("make_join failed") != std::string::npos);
            }
        }
    }
}

SCENARIO("Migration planning rejects unsupported future versions without iterating", "[database][migration][review]")
{
    GIVEN("a far future schema version")
    {
        auto const future_version = merovingian::database::current_schema_version() + 1000000U;

        WHEN("a migration plan is requested")
        {
            auto const plan = merovingian::database::migration_plan_between(future_version, 0U);
            auto const validation = merovingian::database::migration_plan_is_valid(plan);

            THEN("the unsupported range is represented as an invalid bounded plan")
            {
                REQUIRE(plan.current_version == future_version);
                REQUIRE(plan.target_version == 0U);
                REQUIRE(plan.steps.empty());
                REQUIRE_FALSE(validation.valid);
                REQUIRE(validation.reason == "migration plan has no steps");
            }
        }
    }
}

SCENARIO("Migration application reapplies upgrade statements after downgrade", "[database][migration][review]")
{
    GIVEN("a schema upgraded, downgraded, and then upgraded again")
    {
        auto const upgraded = merovingian::database::apply_migration_plan(
            {}, merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));
        REQUIRE(upgraded.ok);
        auto const downgraded = merovingian::database::apply_migration_plan(
            upgraded.state,
            merovingian::database::migration_plan_between(merovingian::database::current_schema_version(), 0U));
        REQUIRE(downgraded.ok);

        WHEN("the schema is upgraded again")
        {
            auto const reapplied = merovingian::database::apply_migration_plan(
                downgraded.state,
                merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));

            THEN("tables are recreated even though migration history still contains the old upgrade record")
            {
                REQUIRE(reapplied.ok);
                REQUIRE(reapplied.state.version == merovingian::database::current_schema_version());
                REQUIRE(reapplied.state.tables.size() == merovingian::database::initial_schema_tables().size());
            }
        }
    }
}

SCENARIO("Persistent store records insert statements only for accepted user and device rows",
         "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("duplicate users and devices are stored")
        {
            auto const first_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const duplicate_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:2", false, false, false});
            auto const first_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const duplicate_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Duplicate laptop"});

            THEN("rejected duplicates do not leave replay statements behind")
            {
                REQUIRE(first_user);
                REQUIRE_FALSE(duplicate_user);
                REQUIRE(first_device);
                REQUIRE_FALSE(duplicate_device);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "insert_user");
                REQUIRE(store.prepared_statements[1].name == "insert_device");
            }
        }
    }
}

SCENARIO("Persistent store rejects duplicate token hashes before recording inserts", "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("the same token hash is stored twice")
        {
            auto const first = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});
            auto const duplicate = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});

            THEN("only one token row and statement are recorded")
            {
                REQUIRE(first);
                REQUIRE_FALSE(duplicate);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 1U);
                REQUIRE(store.prepared_statements.front().name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits login device and token rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("a login transaction is attempted with an invalid token hash")
        {
            auto const rejected = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "plaintext", false});

            THEN("neither durable side effect is recorded")
            {
                REQUIRE_FALSE(rejected);
                REQUIRE(store.devices.empty());
                REQUIRE(store.access_tokens.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }

        WHEN("a login transaction has a new device and hashed token")
        {
            auto const stored = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});

            THEN("the device and access token become visible together")
            {
                REQUIRE(stored);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "insert_device");
                REQUIRE(store.prepared_statements[1].name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits room and state-event rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("a room and state event are stored through transaction helpers")
        {
            auto const room_stored = merovingian::database::store_room_with_membership(
                store, {"!room1:example.org", "@alice:example.org"}, {"!room1:example.org", "@alice:example.org"});
            auto const event_stored = merovingian::database::store_event_with_state(
                store,
                {"$event1:example.org", "!room1:example.org", "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})"},
                merovingian::database::PersistentStateEvent{"!room1:example.org", "m.room.member", "@alice:example.org",
                                                            "$event1:example.org"});

            THEN("the related rows and replay statements are all-or-nothing")
            {
                REQUIRE(room_stored);
                REQUIRE(event_stored);
                REQUIRE(store.rooms.size() == 1U);
                REQUIRE(store.memberships.size() == 1U);
                REQUIRE(store.events.size() == 1U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 4U);
            }
        }
    }
}

SCENARIO("SQLite persistent transactions roll back failed statement groups",
         "[database][sqlite][persistence][transaction][review]")
{
    GIVEN("a SQLite store and a transaction with a duplicate room insert")
    {
        auto const sqlite_path = unique_sqlite_path("rollback");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!room1:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!room1:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the first insert is rolled back with the failing insert")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.prepared_statements.empty());
                REQUIRE(reopened.store.rooms.empty());
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite hydration fails closed when a row reader cannot be prepared",
         "[database][sqlite][persistence][review]")
{
    GIVEN("a SQLite store whose users table no longer matches the expected row shape")
    {
        auto const sqlite_path = unique_sqlite_path("hydrate");
        std::filesystem::remove(sqlite_path);
        auto initialized = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(initialized.ok);
        auto connection = TestSqliteConnection{sqlite_path};
        REQUIRE(connection.execute("ALTER TABLE users RENAME TO users_bad"));
        REQUIRE(connection.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY)"));

        WHEN("the persistent store is opened again")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());

            THEN("startup rejects the partially readable database")
            {
                REQUIRE_FALSE(reopened.ok);
                REQUIRE(reopened.reason == "unable to hydrate SQLite rows");
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store matches state event JSON with whitespace and upserts current state",
         "[database][persistence][review]")
{
    GIVEN("state events with equivalent formatted JSON")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const first_event =
            merovingian::database::store_event(store, {"$event1:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        auto const second_event =
            merovingian::database::store_event(store, {"$event2:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        REQUIRE(first_event);
        REQUIRE(second_event);

        WHEN("the same current-state key is stored twice")
        {
            auto const first_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event1:example.org"});
            auto const second_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event2:example.org"});

            THEN("formatted JSON is accepted and the current-state row is replaced")
            {
                REQUIRE(first_state);
                REQUIRE(second_state);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state.front().event_id == "$event2:example.org");
                REQUIRE(store.prepared_statements.back().name == "upsert_state");
            }
        }
    }
}

SCENARIO("Persisted local event ids are unique across rooms", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with two rooms")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const first_room = merovingian::homeserver::create_room(runtime, login.value);
        auto const second_room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(first_room.ok);
        REQUIRE(second_room.ok);
        auto const initial_event_count = runtime.database.persistent_store.events.size();

        WHEN("one event is sent to each room")
        {
            auto const first_event = merovingian::homeserver::send_event(
                runtime, login.value, first_room.value,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"event-one"}})");
            auto const second_event = merovingian::homeserver::send_event(
                runtime, login.value, second_room.value,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"event-two"}})");

            THEN("event ids do not collide in persistent storage")
            {
                REQUIRE(first_event.ok);
                REQUIRE(second_event.ok);
                REQUIRE(first_event.value != second_event.value);
                REQUIRE(runtime.database.persistent_store.events.size() == initial_event_count + 2U);
                // The last two events are the sent message events; confirm their
                // IDs are distinct (the core non-collision invariant).
                auto const& all_evts = runtime.database.persistent_store.events;
                REQUIRE(all_evts[all_evts.size() - 2U].event_id != all_evts.back().event_id);
            }
        }
    }
}

SCENARIO("Sending a state event mirrors current state", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);
        auto const initial_event_count = runtime.database.persistent_store.events.size();
        auto const initial_state_count = runtime.database.persistent_store.state.size();

        WHEN("a room state event is sent")
        {
            auto const event = merovingian::homeserver::send_event(runtime, login.value, room.value,
                                                                   R"({ "type" : "m.room.topic" , "state_key" : "" })");

            THEN("the event is persisted and materialized as current state")
            {
                REQUIRE(event.ok);
                REQUIRE(runtime.database.persistent_store.events.size() == initial_event_count + 1U);
                REQUIRE(runtime.database.persistent_store.state.size() == initial_state_count + 1U);
                // Verify the topic entry was materialised with the correct event id.
                auto const& state_entries = runtime.database.persistent_store.state;
                auto const topic_it = std::ranges::find_if(state_entries, [](auto const& s) {
                    return s.event_type == "m.room.topic" && s.state_key.empty();
                });
                REQUIRE(topic_it != state_entries.end());
                REQUIRE(topic_it->event_id == event.value);
            }
        }
    }
}

// Regression: leave_room returned 403 "user is not joined or invited" when the
// membership row was absent (server restarted between store_room and store_membership
// during a federated join). The row should be recovered from the current_state table
// before the membership check, allowing the leave to proceed.
SCENARIO("leave_room recovers missing membership row from current state before rejecting with 403",
         "[homeserver][rooms][leave][regression][recovery]")
{
    GIVEN("a started runtime with a registered user whose membership row is absent "
          "but current_state has a join event for a remote room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        // Register and log in the user.
        auto const reg_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("bob", "SecurePass1!")});
        REQUIRE(reg_resp.response.status == 200U);
        auto const login_resp = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"SecurePass1!","device_id":"DEV1"})"});
        REQUIRE(login_resp.response.status == 200U);
        auto const access_token = extract_json_string(login_resp.response.body, "access_token");

        // Simulate a partial join: room stored, join state event stored, but NO
        // membership row — this is the state left behind by a mid-join server restart.
        auto constexpr room_id   = "!partialroom:remote.example.org";
        auto constexpr user_id   = "@bob:example.org";
        auto constexpr event_id  = "$join_ev1:remote.example.org";
        auto const join_event_json = std::string{
            R"({"type":"m.room.member","state_key":")" + std::string{user_id} +
            R"(","sender":")" + std::string{user_id} +
            R"(","room_id":")" + std::string{room_id} +
            R"(","origin_server_ts":1700000000000,"depth":1,)"
            R"("auth_events":[],"prev_events":[],)"
            R"("content":{"membership":"join"}})"};
        {
            auto& store = rt.homeserver.database.persistent_store;
            store.rooms.push_back({std::string{room_id}, std::string{user_id}});
            auto pe            = merovingian::database::PersistentEvent{};
            pe.event_id        = event_id;
            pe.room_id         = room_id;
            pe.sender_user_id  = user_id;
            pe.json            = join_event_json;
            pe.stream_ordering = rt.homeserver.database.next_stream_ordering++;
            auto state = std::optional<merovingian::database::PersistentStateEvent>{
                merovingian::database::PersistentStateEvent{
                    std::string{room_id}, "m.room.member", std::string{user_id}, std::string{event_id}}};
            std::ignore = merovingian::database::store_event_with_state(store, std::move(pe), state);
            // Deliberately do NOT store a membership row.
        }

        WHEN("the user attempts to leave the remote room")
        {
            // outbound_client is null → federation fails → 502 expected.
            // The key assertion is that we do NOT get 403 "user is not joined",
            // which would mean the recovery logic did not fire.
            auto const result = merovingian::homeserver::leave_room(
                rt.homeserver, access_token, room_id);

            THEN("the response is not 403 — membership was recovered from state")
            {
                // 502 = federation not available (null outbound client), which means
                // the recovery path fired and we reached the federated-leave attempt.
                REQUIRE(result.status != 403U);
                REQUIRE(result.status != 404U);
            }
        }
    }
}

// Regression: leave_room for a remote room called persist_membership_transition
// (local-only) instead of making outbound make_leave / send_leave federation calls.
// Verify that the federated leave path is entered by observing a 502 when the
// federation infrastructure is unavailable.
SCENARIO("leave_room takes the federated make_leave/send_leave path for remote rooms",
         "[homeserver][rooms][leave][federation][regression]")
{
    GIVEN("a started runtime with a user joined to a remote room via a persisted membership row")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const reg_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("carol", "SecurePass2!")});
        REQUIRE(reg_resp.response.status == 200U);
        auto const login_resp = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@carol:example.org"},"password":"SecurePass2!","device_id":"DEV2"})"});
        REQUIRE(login_resp.response.status == 200U);
        auto const access_token = extract_json_string(login_resp.response.body, "access_token");

        auto constexpr room_id   = "!fedroom:remote.example.org";
        auto constexpr user_id   = "@carol:example.org";

        {
            auto& store = rt.homeserver.database.persistent_store;
            store.rooms.push_back({std::string{room_id}, std::string{user_id}});
            auto const stream = rt.homeserver.database.next_stream_ordering++;
            std::ignore = merovingian::database::store_membership(
                store, {std::string{room_id}, std::string{user_id}, "join", stream});
        }

        WHEN("the user leaves and the federation infrastructure is unavailable")
        {
            // Ensure outbound_client and discovery_network are null so the
            // federation call returns {false, "federation not available"}.
            rt.homeserver.outbound_client    = nullptr;
            rt.homeserver.discovery_network  = nullptr;

            auto const result = merovingian::homeserver::leave_room(
                rt.homeserver, access_token, room_id);

            THEN("the call fails with 502 indicating the federated leave path was taken")
            {
                // 403 would mean the membership check failed (local path entered).
                // 502 means make_leave was attempted and the remote was unreachable.
                REQUIRE(result.status == 502U);
                REQUIRE(result.ok == false);
                // The reason must mention make_leave, not a membership mismatch.
                REQUIRE(result.reason.find("make_leave") != std::string::npos);
            }
        }
    }
}
