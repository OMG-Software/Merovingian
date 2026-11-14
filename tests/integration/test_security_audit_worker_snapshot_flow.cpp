// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../FederationSigningTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/DatabaseRole.hpp"
#include "merovingian/config/FederationWorkerConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/FederationProxy.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerPool.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <signal.h>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>

namespace
{

using namespace std::chrono_literals;

constexpr auto origin = std::string_view{"remote.example.org"};
constexpr auto remote_key_id = std::string_view{"ed25519:worker-snapshot"};
constexpr auto remote_key_seed = std::string_view{"security-audit-worker-snapshot-seed"};

[[nodiscard]] auto unique_temp_dir() -> std::filesystem::path
{
    auto const root = merovingian::tests::temporary_directory();
    auto const suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto const path = root / ("merovingian-worker-snapshot-" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

class TemporaryDirectory final
{
public:
    TemporaryDirectory()
        : path_{unique_temp_dir()}
    {
    }

    TemporaryDirectory(TemporaryDirectory const&) = delete;
    auto operator=(TemporaryDirectory const&) -> TemporaryDirectory& = delete;
    TemporaryDirectory(TemporaryDirectory&&) = delete;
    auto operator=(TemporaryDirectory&&) -> TemporaryDirectory& = delete;

    ~TemporaryDirectory()
    {
        auto error = std::error_code{};
        std::filesystem::remove_all(path_, error);
    }

    [[nodiscard]] auto path() const noexcept -> std::filesystem::path const&
    {
        return path_;
    }

private:
    std::filesystem::path path_{};
};

// Hide one table that main's room snapshot reads while the worker handles
// room_sync, so the read fails. Hiding the database file no longer does: main
// reads for the worker through readers it opened at start (ADR-0739), which keep
// the original file open. A renamed table is seen by every connection, because
// SQLite checks the schema before each statement. `invites` is read by the
// snapshot and is never written in this scenario, whose room has no invites.
// Destruction is the fallback restore path if an assertion exits early.
class SqliteTableHider final
{
public:
    explicit SqliteTableHider(std::filesystem::path const& database_path)
    {
        if (sqlite3_open_v2(database_path.string().c_str(), &connection_, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK)
        {
            sqlite3_close(connection_);
            connection_ = nullptr;
            return;
        }
        sqlite3_busy_timeout(connection_, 5000);
    }

    SqliteTableHider(SqliteTableHider const&) = delete;
    auto operator=(SqliteTableHider const&) -> SqliteTableHider& = delete;
    SqliteTableHider(SqliteTableHider&&) = delete;
    auto operator=(SqliteTableHider&&) -> SqliteTableHider& = delete;

    ~SqliteTableHider()
    {
        std::ignore = restore();
        sqlite3_close(connection_);
    }

    [[nodiscard]] auto hide() -> bool
    {
        hidden_ = execute("ALTER TABLE invites RENAME TO invites_hidden_by_test");
        return hidden_;
    }

    [[nodiscard]] auto restore() noexcept -> bool
    {
        if (!hidden_)
        {
            return true;
        }
        hidden_ = !execute("ALTER TABLE invites_hidden_by_test RENAME TO invites");
        return !hidden_;
    }

private:
    [[nodiscard]] auto execute(char const* sql) noexcept -> bool
    {
        return connection_ != nullptr && sqlite3_exec(connection_, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    sqlite3* connection_{nullptr};
    bool hidden_{false};
};

[[nodiscard]] auto make_config(std::filesystem::path const& root) -> merovingian::config::Config
{
    using namespace merovingian::config;

    auto server = ServerConfig{};
    auto database = DatabaseConfig{};
    database.backend = DatabaseBackend::sqlite;
    database.sqlite_path = (root / "merovingian.sqlite3").string();
    database.role = DatabaseRole::runtime;

    auto security = SecurityConfig{};
    security.federation.enabled = true;
    security.secrets.master_key_file = merovingian::tests::master_key_file();

    auto federation_worker = FederationWorkerConfig{};
    federation_worker.shards = 2U;
    federation_worker.threads = 1U;
    federation_worker.request_timeout_seconds = 10U;
    federation_worker.apply_hardening = false;
    federation_worker.allow_without_landlock = true;

    return {server,           ListenersConfig{}, database, security, ClientRateLimitsConfig{}, LogModulesConfig{},
            federation_worker};
}

auto write_worker_config(std::filesystem::path const& path, merovingian::config::Config const& config) -> void
{
    auto stream = std::ofstream{path, std::ios::binary};
    REQUIRE(stream.is_open());
    stream << "server.name=" << config.server().server_name << '\n';
    stream << "server.public_baseurl=" << config.server().public_baseurl << '\n';
    stream << "database.backend=sqlite\n";
    stream << "database.sqlite_path=" << config.database().sqlite_path << '\n';
    stream << "database.role=runtime\n";
    stream << "security.federation.enabled=true\n";
    stream << "security.secrets.master_key_file=" << config.security().secrets.master_key_file << '\n';
    stream << "federation.worker.shards=" << config.federation_worker().shards << '\n';
    stream << "federation.worker.threads=" << config.federation_worker().threads << '\n';
    stream << "federation.worker.relay_threads=" << config.federation_worker().relay_threads << '\n';
    stream << "federation.worker.request_timeout_seconds=" << config.federation_worker().request_timeout_seconds
           << '\n';
    stream << "federation.worker.apply_hardening=false\n";
    stream << "federation.worker.allow_without_landlock=true\n";
}

[[nodiscard]] auto test_worker_binary() -> std::string_view
{
#ifndef MEROVINGIAN_TEST_FEDERATION_WORKER
#define MEROVINGIAN_TEST_FEDERATION_WORKER ""
#endif
    return MEROVINGIAN_TEST_FEDERATION_WORKER;
}

[[nodiscard]] auto wait_for_proxy(merovingian::homeserver::FederationProxy& proxy, std::chrono::seconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!proxy.healthy() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(50ms);
    }
    return proxy.healthy();
}

[[nodiscard]] auto make_remote_key_resolver()
{
    return [](std::string_view server_name,
              std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
        if (server_name != origin || key_id != remote_key_id)
        {
            return std::nullopt;
        }
        auto remote = merovingian::federation::FederationRemoteRuntime{};
        remote.server_name = std::string{server_name};
        remote.signing_key = {std::string{server_name}, std::string{key_id}, 4'102'444'800'000U,
                              merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
        remote.discovery.server_name = std::string{server_name};
        remote.discovery.resolved_host = std::string{server_name};
        remote.discovery.resolved_addresses = std::vector<std::string>{"198.51.100.27"};
        remote.trust.reputation_score = 100U;
        return remote;
    };
}

[[nodiscard]] auto x_matrix_authorization(std::string_view destination, std::string_view target) -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, "GET", target, {},
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return std::string{R"(X-Matrix origin=")"} + std::string{origin} + R"(",key=")" + std::string{remote_key_id} +
           R"(",sig=")" + signature + R"(",destination=")" + std::string{destination} + R"(")";
}

[[nodiscard]] auto create_room_and_set_acl(merovingian::homeserver::HomeserverRuntime& runtime,
                                           std::string_view local_server_name)
    -> std::tuple<std::string, std::string, std::string>
{
    auto const admin_user = std::string{"worker_snapshot_admin"};
    auto const registration = merovingian::homeserver::bootstrap_admin_user(runtime, admin_user, "CorrectHorse7!");
    REQUIRE(registration.ok);

    auto const full_admin_user = "@" + admin_user + ":" + std::string{local_server_name};
    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, full_admin_user + "|CorrectHorse7!|SNAPSHOT_ADMIN"});
    REQUIRE(login.status == 200U);

    auto const create = merovingian::homeserver::handle_local_http_request(
        runtime,
        {"POST", "/_matrix/client/v3/createRoom", login.body, R"({"preset":"public_chat","room_version":"10"})"});
    REQUIRE(create.status == 200U);
    auto const room_id = create.body;

    // Make the room world-readable so a remote origin with no joined user can
    // legitimately call /state_ids (the project read gate requires either a
    // joined user or world_readable history). The server ACL then remains the
    // only variable between the two phases of the test.
    auto const history_visibility_target = "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.history_visibility";
    auto const history_visibility = merovingian::homeserver::handle_local_http_request(
        runtime, {"PUT", history_visibility_target, login.body, R"({"history_visibility":"world_readable"})"});
    REQUIRE(history_visibility.status == 200U);

    auto const acl_target = "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.server_acl";
    auto const allow = merovingian::homeserver::handle_local_http_request(
        runtime, {"PUT", acl_target, login.body, R"({"allow":["*"],"deny":[]})"});
    REQUIRE(allow.status == 200U);
    auto const acl_state = std::ranges::find_if(runtime.database.persistent_store.state, [&room_id](auto const& state) {
        return state.room_id == room_id && state.event_type == "m.room.server_acl" && state.state_key.empty();
    });
    REQUIRE(acl_state != runtime.database.persistent_store.state.end());
    return {std::move(room_id), login.body, acl_state->event_id};
}

// A remote server's signed GET /state_ids for a room at an event.
[[nodiscard]] auto signed_state_ids_read(merovingian::config::Config const& config, std::string_view room_id,
                                         std::string_view event_id) -> merovingian::homeserver::LocalHttpRequest
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = "GET";
    request.target = "/_matrix/federation/v1/state_ids/" + std::string{room_id} + "?event_id=" + std::string{event_id};
    request.access_token = x_matrix_authorization(config.server().server_name, request.target);
    request.remote_addr = "198.51.100.27";
    return request;
}

// A remote server's signed PUT /send carrying `body`.
[[nodiscard]] auto signed_send(merovingian::config::Config const& config, std::string_view txn_id, std::string body)
    -> merovingian::homeserver::LocalHttpRequest
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/" + std::string{txn_id};
    auto const destination = config.server().server_name;
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, "PUT", request.target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    request.access_token = std::string{R"(X-Matrix origin=")"} + std::string{origin} + R"(",key=")" +
                           std::string{remote_key_id} + R"(",sig=")" + signature + R"(",destination=")" + destination +
                           R"(")";
    request.body = std::move(body);
    request.remote_addr = "198.51.100.27";
    return request;
}

// A link to the worker binary for a pool to start from. Removing it before killing a worker makes every restart of
// that worker fail, so its shard stays down until the test ends, however slowly the test runs; the pool's teardown
// stops the supervisor's retries.
[[nodiscard]] auto link_worker_binary(std::filesystem::path const& directory) -> std::filesystem::path
{
    auto link = directory / "merovingian-fed-worker";
    std::filesystem::create_symlink(std::filesystem::path{test_worker_binary()}, link);
    return link;
}

auto change_acl_to_deny(merovingian::homeserver::HomeserverRuntime& runtime, std::string_view token,
                        std::string_view room_id) -> void
{
    auto const acl_target = "/_matrix/client/v3/rooms/" + std::string{room_id} + "/state/m.room.server_acl";
    auto const response = merovingian::homeserver::handle_local_http_request(
        runtime, {"PUT", acl_target, std::string{token}, R"({"allow":["*"],"deny":["remote.example.org"]})"});
    REQUIRE(response.status == 200U);
}

} // namespace

SCENARIO("A failed worker room reload cannot serve federation reads with stale ACL state",
         "[security_audit_worker_snapshot][federation][integration]")
{
    GIVEN("a real federation worker that loaded a room while the remote origin was allowed")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // Seal the federation callbacks (pdu_sink etc.) so that the proxy's own
        // call to wire_federation_callbacks returns early and cannot replace the
        // test seam resolver with the production network resolver.
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [room_id, admin_token, initial_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);

        auto proxy = merovingian::homeserver::FederationProxy{
            config.federation_worker(), runtime, std::string{test_worker_binary()}, worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));

        auto const target = "/_matrix/federation/v1/state_ids/" + room_id + "?event_id=" + initial_acl_event_id;
        auto make_signed_read = [&config, &target]() {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = target;
            request.access_token = x_matrix_authorization(config.server().server_name, target);
            request.remote_addr = "198.51.100.27";
            return request;
        };
        auto const initially_allowed = proxy.handle(make_signed_read());
        REQUIRE(initially_allowed.status == 200U);

        WHEN("main commits a denying ACL but the worker cannot reload that room")
        {
            change_acl_to_deny(runtime, admin_token, room_id);

            // Test-only fault injection: hide one table main's room snapshot
            // reads, so the worker's room_sync fails. Main's own state stays in
            // memory and authoritative. Restore before teardown.
            auto database_table = SqliteTableHider{config.database().sqlite_path};
            REQUIRE(database_table.hide());
            proxy.notify_room_changed(room_id);

            // Poll the test-observable room-sync status until the worker reports
            // a failed reload or the deadline expires. Do not infer failure from
            // a sleep or the worker's log output.
            auto const deadline = std::chrono::steady_clock::now() + 5s;
            auto failed_generation = std::uint64_t{0U};
            while (std::chrono::steady_clock::now() < deadline)
            {
                auto const status = proxy.room_sync_status(room_id);
                if (status.state == "failed")
                {
                    failed_generation = status.generation;
                    break;
                }
                std::this_thread::sleep_for(20ms);
            }
            REQUIRE(failed_generation > 0U);
            REQUIRE(database_table.restore());

            auto const response = proxy.handle(make_signed_read());

            THEN("the verified remote receives main's ACL denial instead of stale worker state")
            {
                CHECK(response.status == 403U);
                CHECK(response.body.find("M_FORBIDDEN") != std::string::npos);
                CHECK(proxy.room_sync_status(room_id).generation == failed_generation);
                CHECK(proxy.room_sync_status(room_id).state == "failed");
            }
        }
    }
}

// ADR-0748: Complement TestEventAuth sent a state event, saw it in /sync, and at once asked GET /event_auth for it.
// The worker that owns the room had not reloaded it yet and answered 404. While a reload is pending, main serves the
// room's reads.
SCENARIO("A federation read of an event sent a moment ago is answered while the worker reloads the room",
         "[security_audit_worker_snapshot][federation][integration][adr0748]")
{
    GIVEN("a real federation worker that loaded a world-readable room")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [room_id, admin_token, ignored_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);
        std::ignore = ignored_acl_event_id;

        auto const worker_link = link_worker_binary(temporary.path());
        auto proxy = merovingian::homeserver::FederationProxy{config.federation_worker(), runtime, worker_link.string(),
                                                              worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));
        auto const wait_until = [](auto const& done) {
            auto const deadline = std::chrono::steady_clock::now() + 15s;
            while (!done() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(20ms);
            }
            return done();
        };
        // One reload the worker completes, so the room is one it holds and only a pending reload sends it to main.
        proxy.notify_room_changed(room_id);
        REQUIRE(wait_until([&proxy, &room_id]() {
            return proxy.room_sync_status(room_id).state == "ok";
        }));
        REQUIRE(proxy.room_sync_status(room_id).held);
        // The reload the next change starts must not finish before the read, or the read would pass without the
        // pending fallback. Killing the room's worker with its binary's link removed keeps that reload pending.
        auto const worker = proxy.worker_pid_for_room(room_id);
        REQUIRE(worker > 0);
        REQUIRE(std::filesystem::remove(worker_link));
        REQUIRE(::kill(worker, SIGKILL) == 0);
        REQUIRE(wait_until([&proxy, &room_id]() {
            return proxy.worker_pid_for_room(room_id) == -1 && !proxy.healthy();
        }));

        WHEN("a client sends a state event and a remote server asks for its auth events at once")
        {
            auto const topic = merovingian::homeserver::handle_local_http_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic", admin_token,
                          R"({"topic":"just sent"})"});
            REQUIRE(topic.status == 200U);
            auto const topic_state =
                std::ranges::find_if(runtime.database.persistent_store.state, [&room_id](auto const& state) {
                    return state.room_id == room_id && state.event_type == "m.room.topic" && state.state_key.empty();
                });
            REQUIRE(topic_state != runtime.database.persistent_store.state.end());
            // What send_event_as_user does for the proxy main owns; this test's proxy is its own.
            proxy.notify_room_changed(room_id);
            auto const target = "/_matrix/federation/v1/event_auth/" + room_id + "/" + topic_state->event_id;
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = target;
            request.access_token = x_matrix_authorization(config.server().server_name, target);
            request.remote_addr = "198.51.100.27";
            auto const response = proxy.handle(request);
            auto const status = proxy.room_sync_status(room_id);
            auto const still_down = proxy.worker_pid_for_room(room_id) == -1;

            THEN("the auth chain is returned while the reload is pending, never 404")
            {
                REQUIRE(still_down);
                CHECK(status.state == "pending");
                CHECK(status.held);
                CHECK(response.status == 200U);
                CHECK(response.body.find("auth_chain") != std::string::npos);
            }
        }
    }
}

// ADR-0756: Complement TestKnockingInMSC3787Room created a room and had a remote server join it at once. The worker had
// never loaded the room, took room version 12, computed another event ID than the join's and refused it. A room main
// notifies for the first time is not held by the worker until a reload of it succeeds, and main serves it until then.
SCENARIO("A room created after the worker started is held by the worker only once it has loaded it",
         "[security_audit_worker_snapshot][federation][integration][adr0756]")
{
    GIVEN("a real federation worker started before a room is created")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [listed_room_id, admin_token, listed_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);

        auto proxy = merovingian::homeserver::FederationProxy{
            config.federation_worker(), runtime, std::string{test_worker_binary()}, worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));
        // A healthy channel is not a finished start-up copy. Wait until the worker that owns the listed room serves
        // it, so the table hidden below cannot fail that copy.
        auto const listed_served = [&proxy, &config, &listed_room_id, &listed_acl_event_id]() {
            auto const deadline = std::chrono::steady_clock::now() + 15s;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (proxy.handle(signed_state_ids_read(config, listed_room_id, listed_acl_event_id)).status == 200U)
                {
                    return true;
                }
                std::this_thread::sleep_for(20ms);
            }
            return false;
        }();
        REQUIRE(listed_served);

        auto const create = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", admin_token, R"({"room_version":"10"})"});
        REQUIRE(create.status == 200U);
        auto const new_room_id = create.body;

        auto const wait_for_state = [&proxy, &new_room_id](std::string_view wanted) {
            auto const deadline = std::chrono::steady_clock::now() + 5s;
            while (std::chrono::steady_clock::now() < deadline)
            {
                auto const status = proxy.room_sync_status(new_room_id);
                if (status.state == wanted)
                {
                    return status;
                }
                std::this_thread::sleep_for(20ms);
            }
            return proxy.room_sync_status(new_room_id);
        };

        WHEN("main notifies the worker of the new room and the worker's first load of it fails")
        {
            // Test-only fault injection, as in the failed-reload scenario: hide a table main's snapshot reads.
            auto database_table = SqliteTableHider{config.database().sqlite_path};
            REQUIRE(database_table.hide());
            proxy.notify_room_changed(new_room_id);
            auto const first = wait_for_state("failed");
            REQUIRE(database_table.restore());

            AND_WHEN("a later change is loaded")
            {
                proxy.notify_room_changed(new_room_id);
                auto const second = wait_for_state("ok");

                THEN("the room was not held before its first load and is held after it")
                {
                    CHECK(proxy.room_sync_status(listed_room_id).held);
                    CHECK(first.state == "failed");
                    CHECK_FALSE(first.held);
                    CHECK(second.state == "ok");
                    CHECK(second.held);
                    CHECK(second.generation > first.generation);
                }
            }
        }
    }
}

// ADR-0756: a room the worker's start-up copy left out was reported as held, because main had never notified it, so
// every request for it went to a worker that had no copy of it. The worker reports each room it leaves out, and main
// serves that room until a reload of it succeeds.
SCENARIO("A room the worker's start-up copy left out is served by main until the worker loads it",
         "[security_audit_worker_snapshot][federation][integration][adr0756]")
{
    GIVEN("a room that exists before a worker starts, whose start-up copy fails")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [room_id, admin_token, acl_event_id] = create_room_and_set_acl(runtime, config.server().server_name);
        std::ignore = admin_token;

        // Test-only fault injection: main lists its rooms from `rooms`, but each room's snapshot also reads `invites`.
        auto database_table = SqliteTableHider{config.database().sqlite_path};
        REQUIRE(database_table.hide());
        auto proxy = merovingian::homeserver::FederationProxy{
            config.federation_worker(), runtime, std::string{test_worker_binary()}, worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));

        auto const wait_for_state = [&proxy, &room_id](std::string_view wanted) {
            auto const deadline = std::chrono::steady_clock::now() + 10s;
            while (std::chrono::steady_clock::now() < deadline)
            {
                auto const status = proxy.room_sync_status(room_id);
                if (status.state == wanted)
                {
                    return status;
                }
                std::this_thread::sleep_for(20ms);
            }
            return proxy.room_sync_status(room_id);
        };

        WHEN("the worker reports the room it left out")
        {
            auto const left_out = wait_for_state("failed");
            REQUIRE(database_table.restore());
            // The worker still has no copy of the room, so only main can answer this read before the reload.
            auto const read_before_load = proxy.handle(signed_state_ids_read(config, room_id, acl_event_id));

            AND_WHEN("a later change is loaded")
            {
                proxy.notify_room_changed(room_id);
                auto const loaded = wait_for_state("ok");

                THEN("main served the room until the worker loaded it, and the worker holds it after")
                {
                    CHECK(left_out.state == "failed");
                    CHECK_FALSE(left_out.held);
                    CHECK(left_out.generation == 0U);
                    CHECK(read_before_load.status == 200U);
                    CHECK(loaded.state == "ok");
                    CHECK(loaded.held);
                }
            }
        }
    }
}

// ADR-0756, ADR-0758: every worker's start-up copy lists every room. When the status was kept per room, a shard that
// failed to copy a room another shard owns marked that room as not held although its owner had loaded it. Status is
// kept per shard now: the failed copy is not held on the shard that failed it, and the owner's copy stays held.
SCENARIO("A shard's failed start-up copy of a room is not held on that shard only",
         "[security_audit_worker_snapshot][federation][integration][adr0756][adr0758]")
{
    GIVEN("a pool of two workers, one room owned by each, and the listed room served by its owner")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        REQUIRE(config.federation_worker().shards == 2U);
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [listed_room_id, admin_token, listed_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);
        auto const owner = merovingian::homeserver::federation_worker_shard_for(listed_room_id, 2U);
        auto const other = owner == 0U ? std::size_t{1U} : std::size_t{0U};
        auto other_room_id = std::string{};
        for (auto attempt = 0; attempt < 64 && other_room_id.empty(); ++attempt)
        {
            auto const create = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", admin_token, R"({"room_version":"10"})"});
            REQUIRE(create.status == 200U);
            if (merovingian::homeserver::federation_worker_shard_for(create.body, 2U) == other)
            {
                other_room_id = create.body;
            }
        }
        REQUIRE_FALSE(other_room_id.empty());

        auto proxy = merovingian::homeserver::FederationProxy{
            config.federation_worker(), runtime, std::string{test_worker_binary()}, worker_config_path.string()};
        auto const wait_until = [](auto const& done) {
            auto const deadline = std::chrono::steady_clock::now() + 15s;
            while (!done() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(20ms);
            }
            return done();
        };
        REQUIRE(wait_until([&proxy, &config, &listed_room_id, &listed_acl_event_id]() {
            return proxy.healthy() &&
                   proxy.handle(signed_state_ids_read(config, listed_room_id, listed_acl_event_id)).status == 200U;
        }));

        WHEN("the other shard's worker restarts and its start-up copy fails both rooms")
        {
            // Test-only fault injection, as in the scenarios above: hide a table main's snapshot reads.
            auto database_table = SqliteTableHider{config.database().sqlite_path};
            REQUIRE(database_table.hide());
            auto const killed = proxy.worker_pid_for_room(other_room_id);
            REQUIRE(killed > 0);
            REQUIRE(::kill(killed, SIGKILL) == 0);
            // The restarted worker reports both rooms as left out, and main records both against its shard.
            auto const both_dropped = wait_until([&proxy, other, &other_room_id, &listed_room_id]() {
                return !proxy.room_sync_status(other, other_room_id).held &&
                       !proxy.room_sync_status(other, listed_room_id).held;
            });
            auto const owner_copy = proxy.room_sync_status(owner, listed_room_id);
            auto const owner_view = proxy.room_sync_status(listed_room_id);
            REQUIRE(database_table.restore());

            THEN("both rooms stop being held on the restarted shard only")
            {
                CHECK(both_dropped);
                CHECK(proxy.worker_pid_for_room(other_room_id) != killed);
                CHECK(owner_copy.held);
                CHECK(owner_view.held);
            }
        }
    }
}

// ADR-0758: only the shard that owns a room was told when it changed, so a /send whose first PDU picked another shard
// reached a worker holding a start-up copy of the room, or none. Every shard now reloads every changed room.
SCENARIO("A room created after the workers started is loaded and held by every shard",
         "[security_audit_worker_snapshot][federation][integration][adr0758]")
{
    GIVEN("a pool of two workers started before a room is created")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        REQUIRE(config.federation_worker().shards == 2U);
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [listed_room_id, admin_token, listed_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);
        std::ignore = listed_acl_event_id;

        auto proxy = merovingian::homeserver::FederationProxy{
            config.federation_worker(), runtime, std::string{test_worker_binary()}, worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));

        auto const create = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", admin_token, R"({"room_version":"10"})"});
        REQUIRE(create.status == 200U);
        auto const new_room_id = create.body;
        auto const owner = proxy.shard_for_room(new_room_id);
        auto const other = owner == 0U ? std::size_t{1U} : std::size_t{0U};

        WHEN("main notifies the workers of the new room")
        {
            proxy.notify_room_changed(new_room_id);
            auto const pending_on_other = proxy.room_sync_status(other, new_room_id);
            auto const loaded_everywhere = [&proxy, &new_room_id]() {
                auto const deadline = std::chrono::steady_clock::now() + 10s;
                auto const loaded = [&proxy, &new_room_id](std::size_t shard) {
                    auto const status = proxy.room_sync_status(shard, new_room_id);
                    return status.state == "ok" && status.held;
                };
                while (std::chrono::steady_clock::now() < deadline && !(loaded(0U) && loaded(1U)))
                {
                    std::this_thread::sleep_for(20ms);
                }
                return loaded(0U) && loaded(1U);
            }();
            auto const owner_copy = proxy.room_sync_status(owner, new_room_id);
            auto const other_copy = proxy.room_sync_status(other, new_room_id);

            THEN("the shard that does not own the room loads it too, at the same generation")
            {
                CHECK(pending_on_other.generation == 1U);
                CHECK(loaded_everywhere);
                CHECK(owner_copy.generation == other_copy.generation);
                CHECK(other_copy.held);
                CHECK_FALSE(proxy.room_sync_status(2U, new_room_id).held);
            }
        }
    }
}

// ADR-0758 (CodeRabbit, PR #592): a /send whose first PDU has no room_id goes to shard 0 (ADR-0131), and the proxy
// judged a later PDU's room on the copy of the shard that owns it. When that owner held the room and shard 0 did not,
// the transaction reached a worker with no copy of the room. Every room is now judged on the selected shard's copy.
SCENARIO("A /send whose first PDU has no room is judged on shard 0's copy of every room it names",
         "[security_audit_worker_snapshot][federation][integration][adr0758][adr0131]")
{
    GIVEN("two shards, a room owned by shard 1 that shard 1 holds and shard 0, whose worker is down, does not")
    {
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        REQUIRE(config.federation_worker().shards == 2U);
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.remote_key_resolver = make_remote_key_resolver();
        auto const [first_room_id, admin_token, first_acl_event_id] =
            create_room_and_set_acl(runtime, config.server().server_name);
        std::ignore = first_acl_event_id;
        auto room_id = merovingian::homeserver::federation_worker_shard_for(first_room_id, 2U) == 1U
                           ? std::string{first_room_id}
                           : std::string{};
        for (auto attempt = 0; attempt < 64 && room_id.empty(); ++attempt)
        {
            auto const create = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", admin_token, R"({"room_version":"10"})"});
            REQUIRE(create.status == 200U);
            if (merovingian::homeserver::federation_worker_shard_for(create.body, 2U) == 1U)
            {
                room_id = create.body;
            }
        }
        REQUIRE_FALSE(room_id.empty());

        auto const worker_link = link_worker_binary(temporary.path());
        auto proxy = merovingian::homeserver::FederationProxy{config.federation_worker(), runtime, worker_link.string(),
                                                              worker_config_path.string()};
        REQUIRE(wait_for_proxy(proxy, 15s));
        auto const wait_until = [](auto const& done) {
            auto const deadline = std::chrono::steady_clock::now() + 15s;
            while (!done() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(20ms);
            }
            return done();
        };
        // Shard 0's worker goes down for good (its binary's link removed), so a request sent to it is answered 503.
        auto const shard_zero_worker = proxy.worker_pid_for_room("");
        REQUIRE(shard_zero_worker > 0);
        REQUIRE(std::filesystem::remove(worker_link));
        REQUIRE(::kill(shard_zero_worker, SIGKILL) == 0);
        REQUIRE(wait_until([&proxy]() {
            return proxy.worker_pid_for_room("") == -1 && !proxy.healthy();
        }));
        std::this_thread::sleep_for(200ms);
        // The room's first change marks it not held on every shard; only shard 1 is up to load it again.
        proxy.notify_room_changed(room_id);
        REQUIRE(wait_until([&proxy, &room_id]() {
            auto const status = proxy.room_sync_status(1U, room_id);
            return status.state == "ok" && status.held;
        }));

        WHEN("a remote server sends a transaction whose first PDU has no room_id and whose second is in the room")
        {
            auto const body = std::string{R"({"origin":")"} + std::string{origin} +
                              R"(","origin_server_ts":1700000000000,"pdus":[{"type":"m.room.message"},{"room_id":")" +
                              room_id + R"(","type":"m.room.message","sender":"@remote:)" + std::string{origin} +
                              R"(","content":{"body":"hi"}}],"edus":[]})";
            auto const shard_zero_copy = proxy.room_sync_status(0U, room_id);
            auto const owner_copy = proxy.room_sync_status(room_id);
            auto const response = proxy.handle(signed_send(config, "adr0758-malformed-first", body));
            auto const still_down = proxy.worker_pid_for_room("") == -1;

            THEN("main answers it, because shard 0 holds no copy of the room, though the room's owner does")
            {
                REQUIRE(still_down);
                CHECK(proxy.shard_for_room("") == 0U);
                CHECK(owner_copy.held);
                CHECK_FALSE(shard_zero_copy.held);
                CHECK(response.status == 200U);
            }
        }
    }
}

// ADR-0756: notify_room_changed returned before recording anything when the worker's channel was down, so a room
// first changed then read as held by a worker that may never have loaded it.
SCENARIO("A room first notified while the worker's channel is down is not held by the worker",
         "[security_audit_worker_snapshot][federation][integration][adr0756]")
{
    GIVEN("a worker pool whose worker for the room has just been killed")
    {
        // The first spawn exchanges keys before the pool is built, so a worker that exits at once makes the pool
        // throw. Killing a started worker instead leaves its shard down for the supervisor's restart backoff.
        if (test_worker_binary().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
        REQUIRE(sodium_init() >= 0);

        auto const temporary = TemporaryDirectory{};
        auto const config = make_config(temporary.path());
        auto const worker_config_path = temporary.path() / "merovingian.conf";
        write_worker_config(worker_config_path, config);

        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const worker_link = link_worker_binary(temporary.path());
        auto pool = merovingian::homeserver::WorkerPool{config.federation_worker(), runtime, worker_link.string(),
                                                        worker_config_path.string()};
        auto const wait_until = [](auto const& done) {
            auto const deadline = std::chrono::steady_clock::now() + 15s;
            while (!done() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(20ms);
            }
            return done();
        };
        REQUIRE(wait_until([&pool]() {
            return pool.healthy();
        }));

        auto const room_id = std::string{"!created-while-down:example.org"};
        auto const shard = pool.shard_for(room_id);
        auto const worker = pool.worker_pid(shard);
        REQUIRE(worker > 0);
        // With the link removed the worker is never restarted, so its shard stays down.
        REQUIRE(std::filesystem::remove(worker_link));
        REQUIRE(::kill(worker, SIGKILL) == 0);
        REQUIRE(wait_until([&pool, shard]() {
            return pool.worker_pid(shard) == -1 && !pool.healthy();
        }));
        // The supervisor drops the dead channel just after marking itself unhealthy. Waiting longer is always safe.
        std::this_thread::sleep_for(200ms);

        WHEN("main notifies a room the worker has never loaded")
        {
            auto const before = pool.room_sync_status(room_id);
            pool.notify_room_changed(room_id);
            auto const after = pool.room_sync_status(room_id);
            auto const still_down = pool.worker_pid(shard) == -1;

            THEN("the room was held only by default before, and is pending and not held after")
            {
                REQUIRE(still_down);
                CHECK(before.held);
                CHECK(after.state == "pending");
                CHECK(after.generation == 1U);
                CHECK_FALSE(after.held);
            }
        }
    }
}
