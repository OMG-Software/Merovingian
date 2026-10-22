// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Media uploads and the waits for them, end to end.
//
// ADR-0212: a download of a reserved but empty mxc:// URI may wait for its
// upload. A wait holds a worker, so it is admitted first: on a request thread
// (no media fetch pool) it takes an ADR-0079 client-outbound slot, and every
// wait counts against a global cap kept below media_fetch_threads. A wait that
// is not admitted answers 504 M_NOT_YET_UPLOADED at once, which the spec allows
// ("The content repository MAY respond before the timeout").

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/sqlite_insert_fault.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;

auto const png_bytes = std::string{"\x89PNG\r\n\x1a\npending-upload-image"};

[[nodiscard]] auto sqlite_media_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto pending_config(std::uint32_t media_fetch_threads) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.http.media_fetch_threads = media_fetch_threads;
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& localpart)
    -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json(localpart, "CorrectHorse7!")})
                .response.status == 200U);
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

} // namespace

SCENARIO("An upload the server fails to store is answered as a server error", "[integration][media][sqlite]")
{
    GIVEN("a SQLite store whose media rows cannot be written")
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-media-upload-" + std::to_string(now) + ".sqlite3");
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_media_config(path));
            REQUIRE(started.started);
            auto const alice = login(started.runtime, "alice");
            auto fault = SqliteInsertFault{path, "media", "media_insert_failure"};

            WHEN("an upload is made")
            {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/media/v3/upload",
                                      alice,
                                      png_bytes,
                                      {merovingian::http::Header{"Content-Type", "image/png"}}});

                THEN("it is a 500 with M_UNKNOWN, not a client error code")
                {
                    REQUIRE(response.response.status == 500U);
                    REQUIRE(errcode_of(response) == "M_UNKNOWN");
                }
            }
        }
        std::filesystem::remove(path);
    }
}

// ADR-0211: the stored upload filename crosses from the local router to the
// client API as a response field, never as a header, so a caller that writes a
// local-router response to the wire cannot leak an internal header.
SCENARIO("The local router hands a download's stored filename over outside the headers",
         "[integration][media][upload-filename]")
{
    GIVEN("a file uploaded with a filename")
    {
        auto started = merovingian::homeserver::start_client_server(pending_config(16U));
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");
        auto const uploaded = merovingian::homeserver::handle_local_http_request(
            started.runtime.homeserver,
            {"POST", "/_matrix/media/v3/upload?filename=report.txt", alice, "text/plain|text/plain|clean|hello"});
        REQUIRE(uploaded.status == 200U);
        auto const content_uri = uploaded.body.substr(0U, uploaded.body.find('|'));
        auto const media_id = content_uri.substr(std::string_view{"mxc://example.org/"}.size());

        WHEN("the local router serves the download")
        {
            auto const downloaded = merovingian::homeserver::handle_local_http_request(
                started.runtime.homeserver,
                {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, alice, {}});

            THEN("the filename is in the response's media_filename and in no header")
            {
                REQUIRE(downloaded.status == 200U);
                REQUIRE(downloaded.media_filename == "report.txt");
                REQUIRE(downloaded.headers.empty());
            }
        }
    }
}
