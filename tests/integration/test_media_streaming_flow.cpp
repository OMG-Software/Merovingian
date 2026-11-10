// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0574: a download of stored media larger than one chunk is not read into memory. The response carries a
// MediaBodyStream and the HTTP layer reads it chunk by chunk, each chunk on a connection that is closed before the
// chunk is written. These scenarios fail against the earlier design, which returned every file whole in the body.

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
#include "merovingian/database/MediaBlobRead.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/MediaBodyStream.hpp"
#include "merovingian/homeserver/StreamedBodyResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/StreamedBody.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

struct SqliteHandleCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        std::ignore = sqlite3_close(connection);
    }
};

[[nodiscard]] auto sqlite_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
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
           ("merovingian-media-streaming-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

// Text whose bytes differ from chunk to chunk, so a chunk read from the wrong offset shows.
[[nodiscard]] auto large_text(std::size_t size) -> std::string
{
    auto text = std::string(size, 'a');
    for (auto index = std::size_t{0U}; index < size; ++index)
    {
        text[index] = (index % 80U == 79U) ? '\n' : static_cast<char>('a' + ((index / 80U + index) % 26U));
    }
    return text;
}

struct UploadedMedia final
{
    std::string token{};
    std::string media_id{};
};

[[nodiscard]] auto upload(hs::HomeserverRuntime& runtime, std::string const& body) -> UploadedMedia
{
    REQUIRE(hs::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!").ok);
    auto const login = hs::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    REQUIRE(login.status == 200U);
    auto const uploaded = hs::handle_local_http_request(
        runtime, {"POST", "/_matrix/media/v3/upload", login.body, "text/plain|text/plain|clean|" + body});
    REQUIRE(uploaded.status == 200U);
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(std::string_view{uploaded.body}.starts_with(prefix));
    auto const rest = std::string_view{uploaded.body}.substr(prefix.size());
    return {login.body, std::string{rest.substr(0U, rest.find('|'))}};
}

// Reads a streamed body the way the HTTP layer does, calling `between_chunks` after each chunk is "written".
template <typename BetweenChunks>
[[nodiscard]] auto drain(hs::MediaBodyStream const& stream, std::string& received, std::size_t& peak,
                         BetweenChunks between_chunks) -> hs::StreamedBodyResult
{
    return hs::write_streamed_body(
        stream.size_bytes, db::media_blob_chunk_bytes,
        [&stream](std::uint64_t offset, std::size_t length) {
            return db::read_media_blob_chunk(stream.blob, stream.size_bytes, offset, length);
        },
        [&received, &between_chunks](std::string_view chunk) {
            received.append(chunk);
            return between_chunks();
        },
        &peak);
}

} // namespace

SCENARIO("A download larger than one chunk is streamed from the database", "[p15b][media][database][streaming]")
{
    GIVEN("a SQLite-backed server holding a file several chunks long")
    {
        auto const path = unique_sqlite_path("served");
        auto started = hs::start_client_server(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const text = large_text((3U * db::media_blob_chunk_bytes) + 123U);
        auto const uploaded = upload(runtime.homeserver, text);

        WHEN("it is downloaded through the client API")
        {
            auto const response = hs::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v1/media/download/example.org/" + uploaded.media_id, uploaded.token, {}});

            THEN("the response holds no body bytes and names the stored length for Content-Length")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.empty());
                REQUIRE(response.response.body_stream.has_value());
                REQUIRE(response.response.body_stream->size_bytes == text.size());
            }

            THEN("the headers are the ones a buffered download carries")
            {
                auto content_type = std::string{};
                auto disposition = false;
                for (auto const& [name, value] : response.response.headers)
                {
                    content_type = name == "Content-Type" ? value : content_type;
                    disposition = disposition || name == "Content-Disposition";
                }
                REQUIRE(content_type == "text/plain");
                REQUIRE(disposition);
            }

            THEN("reading the stream chunk by chunk returns identical bytes with one chunk held at most")
            {
                REQUIRE(response.response.body_stream.has_value());
                auto received = std::string{};
                auto peak = std::size_t{0U};
                auto const result = drain(*response.response.body_stream, received, peak, [] {
                    return true;
                });
                REQUIRE(result == hs::StreamedBodyResult::complete);
                REQUIRE(received == text);
                REQUIRE(peak == db::media_blob_chunk_bytes);
            }

            THEN("a client that stops reading holds no database lock between chunks")
            {
                REQUIRE(response.response.body_stream.has_value());
                auto received = std::string{};
                auto peak = std::size_t{0U};
                auto exclusive_lock_granted = true;
                std::ignore = drain(*response.response.body_stream, received, peak, [&path, &exclusive_lock_granted] {
                    // The "client" is stalled here. An exclusive lock is refused while any read transaction is open.
                    sqlite3* raw = nullptr;
                    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
                    auto const connection = std::unique_ptr<sqlite3, SqliteHandleCloser>{raw};
                    if (opened != SQLITE_OK)
                    {
                        exclusive_lock_granted = false;
                        return false;
                    }
                    std::ignore = sqlite3_busy_timeout(connection.get(), 0);
                    auto const began = sqlite3_exec(connection.get(), "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr);
                    exclusive_lock_granted = exclusive_lock_granted && began == SQLITE_OK;
                    std::ignore = sqlite3_exec(connection.get(), "ROLLBACK", nullptr, nullptr, nullptr);
                    return true;
                });
                REQUIRE(exclusive_lock_granted);
            }

            THEN("the bytes changing mid-transfer ends the stream with a read failure, not wrong bytes")
            {
                REQUIRE(response.response.body_stream.has_value());
                auto received = std::string{};
                auto peak = std::size_t{0U};
                auto first = true;
                auto update_result = int{SQLITE_OK};
                auto const result =
                    drain(*response.response.body_stream, received, peak, [&path, &first, &update_result] {
                        if (first)
                        {
                            first = false;
                            sqlite3* raw = nullptr;
                            std::ignore = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
                            auto const connection = std::unique_ptr<sqlite3, SqliteHandleCloser>{raw};
                            update_result =
                                sqlite3_exec(connection.get(), "UPDATE media_blobs SET bytes = CAST('short' AS BLOB)",
                                             nullptr, nullptr, nullptr);
                        }
                        return true;
                    });
                REQUIRE(update_result == SQLITE_OK);
                REQUIRE(result == hs::StreamedBodyResult::read_failed);
                REQUIRE(received.size() == db::media_blob_chunk_bytes);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A download of one chunk or less is still returned whole", "[p15b][media][database][streaming]")
{
    GIVEN("a SQLite-backed server holding a small file")
    {
        auto const path = unique_sqlite_path("small");
        auto started = hs::start_client_server(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const uploaded = upload(runtime.homeserver, "hello");

        WHEN("it is downloaded through the client API")
        {
            auto const response = hs::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v1/media/download/example.org/" + uploaded.media_id, uploaded.token, {}});

            THEN("the bytes are in the body and nothing is streamed")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE_FALSE(response.response.body_stream.has_value());
                REQUIRE(response.response.body == "hello");
            }
        }

        std::filesystem::remove(path);
    }
}
