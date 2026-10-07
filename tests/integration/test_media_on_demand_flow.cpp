// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0119: media bytes live only in the database and are read per request,
// with the runtime mutex released for the read. These scenarios fail against
// the earlier design, which held every file's bytes in memory.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <sqlite3.h>

namespace
{

struct SqliteHandleCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        std::ignore = sqlite3_close(connection);
    }
};

[[nodiscard]] auto sqlite_media_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-media-on-demand-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto admin_token(merovingian::homeserver::HomeserverRuntime& runtime) -> std::string
{
    REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!").ok);
    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    REQUIRE(login.status == 200U);
    return login.body;
}

[[nodiscard]] auto media_id_from_upload(std::string_view body) -> std::string
{
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(body.starts_with(prefix));
    auto const rest = body.substr(prefix.size());
    return std::string{rest.substr(0U, rest.find('|'))};
}

// Replaces every stored blob's bytes behind the server's back, so a download
// can only return the new bytes if it reads the database.
auto overwrite_durable_bytes(std::filesystem::path const& path, std::string const& bytes) -> void
{
    sqlite3* raw = nullptr;
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteHandleCloser>{raw};
    REQUIRE(opened == SQLITE_OK);
    auto const sql = "UPDATE media_blobs SET bytes = CAST('" + bytes + "' AS BLOB)";
    REQUIRE(sqlite3_exec(connection.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

} // namespace

SCENARIO("Media downloads read the stored bytes from the database", "[media-on-demand][media][database]")
{
    GIVEN("a SQLite-backed server holding an uploaded file")
    {
        auto const path = unique_sqlite_path("served");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        auto const uploaded = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
        REQUIRE(uploaded.status == 200U);
        auto const media_id = media_id_from_upload(uploaded.body);

        WHEN("the durable bytes change underneath the running server and the file is downloaded")
        {
            overwrite_durable_bytes(path, "world");
            auto const downloaded = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});

            THEN("the bytes come from the database, not from a copy held in memory")
            {
                REQUIRE(downloaded.status == 200U);
                REQUIRE(downloaded.body == "text/plain|world");
            }

            THEN("the store's in-memory blob row carries no bytes")
            {
                REQUIRE(runtime.database.persistent_store.media_blobs.size() == 1U);
                REQUIRE(runtime.database.persistent_store.media_blobs.front().bytes.empty());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A deduplicated upload updates the reference count without rewriting the bytes",
         "[media-on-demand][media][database]")
{
    GIVEN("a SQLite-backed server recording its committed statements")
    {
        auto const path = unique_sqlite_path("dedup");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        merovingian::database::enable_statement_capture(runtime.database.persistent_store, 256U);

        WHEN("the same file is uploaded twice")
        {
            for (auto i = 0; i < 2; ++i)
            {
                REQUIRE(merovingian::homeserver::handle_local_http_request(
                            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"})
                            .status == 200U);
            }
            auto upserts = std::size_t{0U};
            auto ref_count_updates = std::size_t{0U};
            for (auto const& statement : runtime.database.persistent_store.captured_statements)
            {
                upserts += statement.name == "upsert_media_blob" ? 1U : 0U;
                ref_count_updates += statement.name == "update_media_blob_ref_count" ? 1U : 0U;
            }

            THEN("the bytes are written once and the second upload only bumps the reference count")
            {
                REQUIRE(upserts == 1U);
                REQUIRE(ref_count_updates == 1U);
            }
        }

        std::filesystem::remove(path);
    }
}

// The federation core calls its media provider without the runtime mutex.
// The provider must take it for the repository lookups, which rebuild their
// indices, or it races with uploads; ThreadSanitizer reports that race here.
SCENARIO("Federation media downloads run safely alongside uploads", "[media-on-demand][media][concurrency]")
{
    GIVEN("a server holding a file, with one thread downloading it over federation while another uploads")
    {
        auto const path = unique_sqlite_path("concurrent");
        auto started = merovingian::homeserver::start_runtime(sqlite_media_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = admin_token(runtime);
        auto const uploaded = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|shared"});
        REQUIRE(uploaded.status == 200U);
        auto const media_id = media_id_from_upload(uploaded.body);

        WHEN("both run at once")
        {
            constexpr auto rounds = 25;
            auto release = std::atomic<bool>{false};
            auto served = std::atomic<int>{0};
            auto downloader = std::thread{[&runtime, &media_id, &release, &served] {
                while (!release.load())
                {
                    std::this_thread::yield();
                }
                for (auto i = 0; i < rounds; ++i)
                {
                    auto const result = merovingian::homeserver::download_local_media_for_federation(runtime, media_id);
                    if (result.ok && result.bytes == "shared")
                    {
                        served.fetch_add(1);
                    }
                }
            }};
            auto upload_statuses = std::vector<std::uint16_t>{};
            release.store(true);
            for (auto i = 0; i < rounds; ++i)
            {
                upload_statuses.push_back(merovingian::homeserver::handle_local_http_request(
                                              runtime, {"POST", "/_matrix/media/v3/upload", token,
                                                        "text/plain|text/plain|clean|upload-" + std::to_string(i)})
                                              .status);
            }
            downloader.join();

            THEN("every federation download returns the file and every upload succeeds")
            {
                REQUIRE(served.load() == rounds);
                for (auto const status : upload_statuses)
                {
                    REQUIRE(status == 200U);
                }
            }
        }

        std::filesystem::remove(path);
    }
}
