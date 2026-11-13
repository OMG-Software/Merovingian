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
#include "merovingian/homeserver/FederationProxy.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
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
