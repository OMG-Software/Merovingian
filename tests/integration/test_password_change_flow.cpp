// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A password change end to end, on a real SQLite database: the auth service, the store and a
// write the database itself refuses. A change that cannot finish must commit nothing a client
// would have to undo, in memory or on disk.
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

#include <sqlite3.h>

namespace
{

// Removes the database file and its journal files when the scenario ends.
class SqliteFileCleanup final
{
public:
    explicit SqliteFileCleanup(std::filesystem::path path)
        : path_{std::move(path)}
    {
    }
    ~SqliteFileCleanup() noexcept
    {
        auto error = std::error_code{};
        for (auto const suffix : {"", "-wal", "-shm", "-journal"})
        {
            std::ignore = std::filesystem::remove(path_.string() + suffix, error);
        }
    }
    SqliteFileCleanup(SqliteFileCleanup const&) = delete;
    auto operator=(SqliteFileCleanup const&) -> SqliteFileCleanup& = delete;
    SqliteFileCleanup(SqliteFileCleanup&&) = delete;
    auto operator=(SqliteFileCleanup&&) -> SqliteFileCleanup& = delete;

private:
    std::filesystem::path path_;
};

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

// A second connection to the server's database file: it installs a trigger that makes one table
// refuse deletes, as a failing disk or a constraint would, and reads back what was persisted.
class SqliteProbe final
{
public:
    explicit SqliteProbe(std::filesystem::path const& path)
    {
        auto* raw_connection = static_cast<sqlite3*>(nullptr);
        auto const status = sqlite3_open(path.string().c_str(), &raw_connection);
        connection_.reset(raw_connection);
        REQUIRE(status == SQLITE_OK);
    }

    auto refuse_deletes_from(std::string_view table) -> void
    {
        REQUIRE(sqlite3_exec(connection_.get(),
                             ("CREATE TRIGGER refuse_delete BEFORE DELETE ON " + std::string{table} +
                              " BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END")
                                 .c_str(),
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    // The single text value `sql` selects, with `parameter` bound to its one placeholder.
    [[nodiscard]] auto text(std::string_view sql, std::string_view parameter) const -> std::optional<std::string>
    {
        auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
        REQUIRE(sqlite3_prepare_v2(connection_.get(), std::string{sql}.c_str(), -1, &raw_statement, nullptr) ==
                SQLITE_OK);
        auto const statement =
            std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>{raw_statement, &sqlite3_finalize};
        REQUIRE(sqlite3_bind_text(statement.get(), 1, parameter.data(), static_cast<int>(parameter.size()), nullptr) ==
                SQLITE_OK);
        if (sqlite3_step(statement.get()) != SQLITE_ROW)
        {
            return std::nullopt;
        }
        auto const* value = sqlite3_column_text(statement.get(), 0);
        return value == nullptr ? std::nullopt : std::optional<std::string>{reinterpret_cast<char const*>(value)};
    }

private:
    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
};

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

// POST /account/password with `logout_devices` (default true) revokes the user's other devices,
// and this server also deletes the pushers those devices set (ADR-0264). The deletions run before
// the password or any token is written, so a failed deletion leaves the old password valid and
// the request can be retried.
SCENARIO("change_local_user_password commits nothing when a revoked device's pusher cannot be removed",
         "[integration][auth][password_change][security][db-5][password-change-pushers]")
{
    GIVEN("a user signed in on two devices on a SQLite database, with a pusher set from the other device")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-password-change-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        auto const cleanup = SqliteFileCleanup{path};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const caller = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(caller.ok);
        auto const other = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE2");
        REQUIRE(other.ok);
        auto pusher = merovingian::database::PersistentPusher{};
        pusher.user_id = reg.value;
        pusher.app_id = "com.example.app";
        pusher.pushkey = "device2-key";
        pusher.kind = "http";
        pusher.device_id = "DEVICE2";
        REQUIRE(merovingian::database::store_pusher(runtime.database.persistent_store, pusher));

        auto probe = SqliteProbe{path};
        auto const hash_before = probe.text("SELECT password_hash FROM users WHERE user_id = ?1", reg.value);
        REQUIRE(hash_before.has_value());

        WHEN("the database refuses to delete that pusher during a password change")
        {
            probe.refuse_deletes_from("pushers");
            auto const result =
                merovingian::homeserver::change_local_user_password(runtime, caller.value, "NewPassword99!");

            THEN("the change is reported as failed and the running server changed nothing")
            {
                // A failure must mean the password is unchanged, so the client can retry with the old one.
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE3").ok);
                REQUIRE_FALSE(
                    merovingian::homeserver::login_local_user(runtime, reg.value, "NewPassword99!", "DEVICE4").ok);
                // The other device keeps its session, since its tokens were never revoked.
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, other.value).has_value());
            }

            AND_THEN("the database holds the old password, the pusher, and the other device's live tokens")
            {
                REQUIRE(probe.text("SELECT password_hash FROM users WHERE user_id = ?1", reg.value) == hash_before);
                REQUIRE(probe.text("SELECT pushkey FROM pushers WHERE device_id = ?1", "DEVICE2") ==
                        std::optional<std::string>{"device2-key"});
                REQUIRE_FALSE(
                    probe
                        .text("SELECT token_hash FROM access_tokens WHERE device_id = ?1 AND revoked = 'true'",
                              "DEVICE2")
                        .has_value());
            }
        }
    }
}
