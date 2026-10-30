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
#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/sqlite_insert_fault.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>

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

[[nodiscard]] auto reserve(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const response =
        merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/media/v1/create", token, {}});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* content_uri = string_member(body, "content_uri");
    REQUIRE(content_uri != nullptr);
    return content_uri->substr(std::string_view{"mxc://example.org/"}.size());
}

[[nodiscard]] auto download(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                            std::string const& media_id, std::uint32_t timeout_ms)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime,
        {"GET",
         "/_matrix/client/v1/media/download/example.org/" + media_id + "?timeout_ms=" + std::to_string(timeout_ms),
         token,
         {}});
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

} // namespace

SCENARIO("A pending-upload wait on a request thread needs a client-outbound slot",
         "[integration][media][async-upload][security]")
{
    GIVEN("a reserved, empty mxc:// URI and a client-outbound budget with no slots")
    {
        auto started = merovingian::homeserver::start_client_server(pending_config(16U));
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");
        auto const media_id = reserve(started.runtime, alice);
        started.runtime.homeserver.client_outbound_proxy_policy.global_cap = 0U;

        WHEN("it is downloaded with a long timeout and no media fetch pool")
        {
            auto const started_at = std::chrono::steady_clock::now();
            auto const response = download(started.runtime, alice, media_id, 5000U);
            auto const waited = std::chrono::steady_clock::now() - started_at;

            THEN("the request thread does not wait: the answer is 504 M_NOT_YET_UPLOADED at once")
            {
                REQUIRE(response.response.status == 504U);
                REQUIRE(errcode_of(response) == "M_NOT_YET_UPLOADED");
                REQUIRE(waited < std::chrono::seconds{2});
                REQUIRE(started.runtime.homeserver.media_upload_notifier->waiting() == 0U);
            }
        }
    }
}

SCENARIO("Concurrent pending-upload waits stay below the media fetch pool's size",
         "[integration][media][async-upload][security]")
{
    GIVEN("a server with two media fetch workers, so at most one wait at a time, and a reserved URI")
    {
        auto started = merovingian::homeserver::start_client_server(pending_config(2U));
        REQUIRE(started.started);
        // Room in the client-outbound budget, so only the wait cap can refuse.
        started.runtime.homeserver.client_outbound_proxy_policy.global_cap = 8U;
        started.runtime.homeserver.client_outbound_proxy_policy.per_client_cap = 8U;
        auto const alice = login(started.runtime, "alice");
        auto const bob = login(started.runtime, "bob");
        auto const media_id = reserve(started.runtime, alice);

        WHEN("one download is waiting and a second asks to wait")
        {
            auto waiter_status = std::uint16_t{0U};
            auto threads = merovingian::tests::JoiningThreads{};
            threads.emplace_back([&started, &alice, &media_id, &waiter_status] {
                waiter_status = download(started.runtime, alice, media_id, 10000U).response.status;
            });
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (started.runtime.homeserver.media_upload_notifier->waiting() == 0U &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            }
            auto const first_was_waiting = started.runtime.homeserver.media_upload_notifier->waiting() == 1U;
            auto const second_started_at = std::chrono::steady_clock::now();
            auto const second = download(started.runtime, bob, media_id, 5000U);
            auto const second_waited = std::chrono::steady_clock::now() - second_started_at;
            auto const uploaded = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT",
                                  "/_matrix/media/v3/upload/example.org/" + media_id,
                                  alice,
                                  png_bytes,
                                  {merovingian::http::Header{"Content-Type", "image/png"}}});
            threads.join();

            THEN("the second is answered 504 at once and the first is still served when the content arrives")
            {
                REQUIRE(first_was_waiting);
                REQUIRE(second.response.status == 504U);
                REQUIRE(errcode_of(second) == "M_NOT_YET_UPLOADED");
                REQUIRE(second_waited < std::chrono::seconds{2});
                REQUIRE(uploaded.response.status == 200U);
                REQUIRE(waiter_status == 200U);
            }
        }
    }

    GIVEN("a server with a single media fetch worker and a reserved URI")
    {
        auto started = merovingian::homeserver::start_client_server(pending_config(1U));
        REQUIRE(started.started);
        // Room in the client-outbound budget, so only the wait cap can refuse.
        started.runtime.homeserver.client_outbound_proxy_policy.global_cap = 8U;
        started.runtime.homeserver.client_outbound_proxy_policy.per_client_cap = 8U;
        auto const alice = login(started.runtime, "alice");
        auto const media_id = reserve(started.runtime, alice);

        WHEN("a download asks to wait for the upload")
        {
            auto const started_at = std::chrono::steady_clock::now();
            auto const response = download(started.runtime, alice, media_id, 5000U);
            auto const waited = std::chrono::steady_clock::now() - started_at;

            THEN("no wait may take the only worker: the answer is 504 M_NOT_YET_UPLOADED at once")
            {
                REQUIRE(response.response.status == 504U);
                REQUIRE(errcode_of(response) == "M_NOT_YET_UPLOADED");
                REQUIRE(waited < std::chrono::seconds{2});
                REQUIRE(started.runtime.homeserver.media_upload_notifier->waiting() == 0U);
            }
        }
    }
}

// Spec: Server-Server API v1.19, GET /_matrix/federation/v1/media/thumbnail/{mediaId}: "504: The
// content is not yet available. A standard error response will be returned with the errcode
// M_NOT_YET_UPLOADED." The request is answered at once (the spec lets the server respond before
// `timeout_ms`): inbound federation has no media fetch pool to wait on (ADR-0212), and an unknown ID is 404.
SCENARIO("A federation thumbnail of a reserved or unknown local media ID is answered at once",
         "[integration][media][async-upload][fed-endpoints]")
{
    GIVEN("a server with one reserved, empty mxc:// URI")
    {
        auto started = merovingian::homeserver::start_client_server(pending_config(16U));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime.homeserver);
        REQUIRE(static_cast<bool>(started.runtime.homeserver.federation.media_thumbnail_provider));
        auto const alice = login(started.runtime, "alice");
        auto const media_id = reserve(started.runtime, alice);
        auto const ask = [&](std::string const& id) {
            auto query = merovingian::federation::FederationThumbnailQuery{};
            query.media_id = id;
            query.width = 32U;
            query.height = 32U;
            query.origin = "remote.example.net";
            return started.runtime.homeserver.federation.media_thumbnail_provider(query);
        };

        WHEN("the reserved ID and an unknown ID are asked for")
        {
            auto const started_at = std::chrono::steady_clock::now();
            auto const reserved = ask(media_id);
            auto const waited = std::chrono::steady_clock::now() - started_at;
            auto const unknown = ask("neverAllocated");

            THEN("the reserved one is 504 without waiting and the unknown one is 404")
            {
                REQUIRE_FALSE(reserved.ok);
                REQUIRE(reserved.status == 504U);
                REQUIRE(waited < std::chrono::seconds{2});
                REQUIRE_FALSE(unknown.ok);
                REQUIRE(unknown.status == 404U);
            }
        }
    }
}

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
