// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/media/security.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <sqlite3.h>

namespace
{

[[nodiscard]] auto media_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.max_upload_size = "8B";
    security.media.quarantine_unknown_mime = false;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto sqlite_media_test_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.max_upload_size = "8B";
    security.media.quarantine_unknown_mime = false;
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-media-integration-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto media_id_from_upload_response(std::string_view body) -> std::string
{
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(body.starts_with(prefix));
    auto const after_prefix = body.substr(prefix.size());
    auto const separator = after_prefix.find('|');
    REQUIRE(separator != std::string_view::npos);
    return std::string{after_prefix.substr(0U, separator)};
}

[[nodiscard]] auto register_and_login_admin(merovingian::homeserver::HomeserverRuntime& runtime) -> std::string
{
    auto const registration = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
    REQUIRE(registration.ok);

    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    REQUIRE(login.status == 200U);
    return login.body;
}

} // namespace

namespace
{

struct SqliteHandleCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        std::ignore = sqlite3_close(connection);
    }
};

struct SqliteStatementFinalizer final
{
    auto operator()(sqlite3_stmt* statement) const noexcept -> void
    {
        std::ignore = sqlite3_finalize(statement);
    }
};

// ADR-0119: the length of every media blob's durable bytes, read straight from
// the SQLite file, since the server keeps no copy of them in memory.
[[nodiscard]] auto durable_blob_lengths(std::filesystem::path const& path) -> std::vector<std::int64_t>
{
    auto lengths = std::vector<std::int64_t>{};
    sqlite3* raw_connection = nullptr;
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw_connection, SQLITE_OPEN_READONLY, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteHandleCloser>{raw_connection};
    if (opened != SQLITE_OK)
    {
        return lengths;
    }
    sqlite3_stmt* raw_statement = nullptr;
    if (sqlite3_prepare_v2(connection.get(), "SELECT length(bytes) FROM media_blobs", -1, &raw_statement, nullptr) !=
        SQLITE_OK)
    {
        return lengths;
    }
    auto const statement = std::unique_ptr<sqlite3_stmt, SqliteStatementFinalizer>{raw_statement};
    while (sqlite3_step(statement.get()) == SQLITE_ROW)
    {
        lengths.push_back(sqlite3_column_int64(statement.get(), 0));
    }
    return lengths;
}

} // namespace

SCENARIO("Removed media can be re-uploaded durably and erased again", "[med-3][media][database][restart]")
{
    GIVEN("a SQLite repository with removed and then re-uploaded content")
    {
        auto const path = unique_sqlite_path();
        auto const config = sqlite_media_test_config(path);
        auto token = std::string{};
        auto media_id = std::string{};
        {
            auto started = merovingian::homeserver::start_runtime(config);
            REQUIRE(started.started);
            token = register_and_login_admin(started.runtime);
            auto const first = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            REQUIRE(first.status == 200U);
            auto const first_id = media_id_from_upload_response(first.body);
            auto const removed = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_merovingian/admin/media/remove/" + first_id, token, "remove first copy"});
            REQUIRE(removed.status == 200U);
            auto const second = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            REQUIRE(second.status == 200U);
            media_id = media_id_from_upload_response(second.body);
        }
        WHEN("the repository restarts and the re-upload is removed")
        {
            {
                auto restarted = merovingian::homeserver::start_runtime(config);
                REQUIRE(restarted.started);
                auto const downloaded = merovingian::homeserver::handle_local_http_request(
                    restarted.runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});
                auto const removed = merovingian::homeserver::handle_local_http_request(
                    restarted.runtime,
                    {"POST", "/_merovingian/admin/media/remove/" + media_id, token, "remove re-upload"});
                THEN("the original bytes survived restart and removal clears every stored copy")
                {
                    CHECK(downloaded.status == 200U);
                    CHECK(downloaded.body == "text/plain|hello");
                    CHECK(removed.status == 200U);
                    CHECK(restarted.runtime.media_repository.blobs.size() == 1U);
                    for (auto const& blob : restarted.runtime.media_repository.blobs)
                    {
                        CHECK(blob.ref_count == 0U);
                    }
                    for (auto const& blob : restarted.runtime.database.persistent_store.media_blobs)
                    {
                        CHECK(blob.ref_count == 0U);
                    }
                    auto const lengths = durable_blob_lengths(path);
                    CHECK(lengths.size() == 1U);
                    for (auto const length : lengths)
                    {
                        CHECK(length == 0);
                    }
                }
            }
            auto reopened = merovingian::homeserver::start_runtime(config);
            REQUIRE(reopened.started);
            for (auto const& blob : reopened.runtime.media_repository.blobs)
            {
                CHECK(blob.ref_count == 0U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Integrated local media repository flow covers upload download dedupe quarantine release "
         "remove and metrics",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with media upload limits")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("local media is uploaded and administered through HTTP routes")
        {
            auto const first_upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            auto const first_media_id = media_id_from_upload_response(first_upload.body);
            auto const duplicate_upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            auto const download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + first_media_id, token, {}});
            auto const quarantine = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/quarantine/" + first_media_id, token, "policy review"});
            auto const blocked_download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + first_media_id, token, {}});
            auto const release = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/release/" + first_media_id, token, {}});
            auto const released_download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + first_media_id, token, {}});
            auto const remove = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/remove/" + first_media_id, token, "operator removal"});
            auto const removed_download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + first_media_id, token, {}});
            auto const metrics = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/media/metrics", token, {}});

            THEN("media bytes are served only while available and metadata/audit paths are updated")
            {
                REQUIRE(first_upload.status == 200U);
                REQUIRE(first_upload.body.find("deduplicated=false") != std::string::npos);
                REQUIRE(duplicate_upload.status == 200U);
                REQUIRE(duplicate_upload.body.find("deduplicated=true") != std::string::npos);
                REQUIRE(download.status == 200U);
                REQUIRE(download.body == "text/plain|hello");
                REQUIRE(quarantine.status == 200U);
                REQUIRE(blocked_download.status == 451U);
                REQUIRE(blocked_download.body == "media is quarantined");
                REQUIRE(release.status == 200U);
                REQUIRE(released_download.status == 200U);
                REQUIRE(remove.status == 200U);
                REQUIRE(removed_download.status == 404U);
                REQUIRE(runtime.media_repository.blobs.size() == 1U);
                REQUIRE(runtime.media_repository.blobs.front().ref_count == 1U);
                REQUIRE(runtime.database.persistent_store.local_media.size() == 2U);
                REQUIRE(runtime.database.persistent_store.admin_actions.size() == 3U);
                REQUIRE(std::ranges::any_of(runtime.database.persistent_store.audit_log, [](auto const& event) {
                    return event.category == "moderation" && event.event_type == "media.quarantined";
                }));
                REQUIRE(metrics.status == 200U);
                REQUIRE(metrics.body.find("media_uploads_accepted_total=2") != std::string::npos);
                REQUIRE(metrics.body.find("media_deduplicated_uploads_total=1") != std::string::npos);
                REQUIRE(metrics.body.find("media_admin_removals_total=1") != std::string::npos);
            }
        }
    }
}

// Security audit finding: admin media routes extracted the raw path suffix
// as the media ID with no validation, unlike the download/thumbnail routes
// (local_media_download_parts) which strip query strings and reject
// embedded slashes. A request like ".../remove/<id>?reason=x" would treat
// the query string as part of the media ID, silently acting on the wrong
// object (or none) instead of the intended one. Fixed via
// admin_media_id_from_suffix() in local_http_router.cpp.
SCENARIO("Admin media routes reject query strings and path-confusion characters in the media ID",
         "[media][repository][integration][security]")
{
    GIVEN("a running homeserver with an uploaded, quarantinable media item")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        auto const upload = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
        auto const media_id = media_id_from_upload_response(upload.body);

        WHEN("a quarantine request's media ID is followed by a query string")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_merovingian/admin/media/quarantine/" + media_id + "?reason=x", token, "policy review"});

            THEN("the query string is stripped and the correct object is quarantined, not left as a stale no-op")
            {
                // Before the fix, the raw "?reason=x" suffix was treated as part
                // of the media ID, so no record matched it and the intended
                // media item was silently left untouched — success from the
                // caller's perspective while nothing actually happened.
                REQUIRE(result.status == 200U);
                REQUIRE(runtime.media_repository.records.front().state ==
                        merovingian::media::LocalMediaState::quarantined);
            }
        }

        WHEN("a remove request's media ID contains a path traversal sequence")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/remove/../" + media_id, token, "operator removal"});

            THEN("the request is rejected outright")
            {
                REQUIRE(result.status == 400U);
                REQUIRE(runtime.media_repository.records.front().state ==
                        merovingian::media::LocalMediaState::available);
            }
        }

        WHEN("a release request's media ID is empty")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/release/", token, {}});

            THEN("the request is rejected outright")
            {
                REQUIRE(result.status == 400U);
            }
        }
    }
}

// Regression test for #444: local_media_download_parts() (the route parser
// for GET .../download/{server_name}/{media_id} and .../thumbnail/...)
// accepted ".." and embedded spaces in the media_id segment, unlike
// media_id_is_safe() at the repository boundary (#443). A crafted URL parsed
// into a traversal-shaped media_id that any code inspecting or routing on it
// before the repository layer would see unvalidated. Fixed by applying the
// same rejection rules the route parser already uses for admin media routes
// (admin_media_id_from_suffix()).
SCENARIO("Media download and thumbnail routes reject path traversal and embedded spaces in the media ID",
         "[media][repository][integration][security]")
{
    GIVEN("a running homeserver")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("a download request's media_id segment contains a path traversal sequence")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/example.org/../secret", {}, {}});

            THEN("the route is rejected as not found rather than parsing a traversal-shaped media_id")
            {
                REQUIRE(result.status == 404U);
            }
        }

        WHEN("a download request's media_id segment contains an embedded space")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/example.org/has space", {}, {}});

            THEN("the route is rejected as not found")
            {
                REQUIRE(result.status == 404U);
            }
        }

        WHEN("a thumbnail request's media_id segment contains a path traversal sequence")
        {
            auto const result = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/media/v3/thumbnail/example.org/../secret?width=32&height=32&method=crop", {}, {}});

            THEN("the route is rejected as not found")
            {
                REQUIRE(result.status == 404U);
            }
        }
    }
}

SCENARIO("Integrated media repository restores durable blob storage after restart",
         "[media][repository][integration][persistence]")
{
    GIVEN("a SQLite-backed homeserver with uploaded media")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_media_test_config(sqlite_path);
        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);
        auto const upload = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
        REQUIRE(upload.status == 200U);
        auto const media_id = media_id_from_upload_response(upload.body);

        WHEN("the runtime is restarted against the same database")
        {
            auto restarted = merovingian::homeserver::start_runtime(config);
            REQUIRE(restarted.started);
            auto after_restart = std::move(restarted.runtime);
            auto const downloaded = merovingian::homeserver::handle_local_http_request(
                after_restart, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});

            THEN("media metadata and blob bytes are available without re-upload")
            {
                REQUIRE(downloaded.status == 200U);
                REQUIRE(downloaded.body == "text/plain|hello");
                REQUIRE(after_restart.database.persistent_store.media_blobs.size() == 1U);
                REQUIRE(after_restart.media_repository.blobs.size() == 1U);
                REQUIRE(after_restart.media_repository.metrics.stored_blobs == 1U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Integrated media upload rejects oversized and unknown MIME uploads", "[media][repository][integration]")
{
    GIVEN("a running homeserver with strict media policy")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("unsafe uploads are submitted")
        {
            auto const oversized = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|too-large"});
            auto const unknown_mime = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/media/v3/upload", token, "application/x-evil|application/x-evil|clean|evil"});
            auto const scanner_failure = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|dirty|clean"});

            THEN("oversized and unknown MIME uploads are rejected and scanner failures are "
                 "quarantined")
            {
                REQUIRE(oversized.status == 413U);
                REQUIRE(oversized.body == "media upload exceeds size limit");
                REQUIRE(unknown_mime.status == 415U);
                REQUIRE(unknown_mime.body == "media MIME type is not allowed");
                REQUIRE(scanner_failure.status == 202U);
                REQUIRE(scanner_failure.body.find("quarantined=true") != std::string::npos);
                REQUIRE(runtime.media_repository.metrics.uploads_rejected == 2U);
                REQUIRE(runtime.media_repository.metrics.uploads_quarantined == 1U);
            }
        }
    }
}

SCENARIO("Remote media download is refused with 404 while remote fetching is disabled",
         "[media][repository][integration][out-7]")
{
    GIVEN("a running homeserver with the default security.media.remote_fetch_enabled=false")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("a remote media download is requested")
        {
            auto const remote = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/remote.example.org/media123", {}, {}});

            THEN("the request is answered 404 before any discovery and the refusal is counted")
            {
                REQUIRE(remote.status == 404U);
                REQUIRE(remote.body == "media not found");
                REQUIRE(runtime.media_repository.metrics.remote_fetch_rejections == 1U);
            }
        }
    }
}

SCENARIO("Remote media download falls back to 502 when server discovery fails", "[media][repository][integration]")
{
    GIVEN("a running homeserver with remote fetching enabled and an unresolvable remote origin")
    {
        auto config = media_test_config();
        config.security().media.remote_fetch_enabled = true;
        auto started = merovingian::homeserver::start_runtime(std::move(config));
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("a remote media download is requested for an unresolvable server")
        {
            // remote.example.org resolves to a blocked/non-Matrix IP; live server
            // discovery via the system network will fail and return !discovery_allowed.
            auto const remote = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/remote.example.org/media123", {}, {}});

            THEN("the request fails closed with 502 and is audited")
            {
                REQUIRE(remote.status == 502U);
                REQUIRE(remote.body == "server discovery failed");
                REQUIRE(runtime.media_repository.metrics.remote_fetch_rejections == 1U);
                REQUIRE(runtime.database.audit_events.back().event_type == "media.remote_fetch_rejected");
            }
        }
    }
}

SCENARIO("Integrated media routes preserve authentication and repository status codes",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with media upload limits")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("unauthenticated and missing-media requests reach media routes")
        {
            auto const unauthenticated_upload = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", {}, "text/plain|text/plain|clean|hello"});
            auto const missing_release = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/release/missing-media", token, {}});
            auto const unauthenticated_quarantine = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/quarantine/missing-media", {}, "policy review"});

            THEN("authentication failures and repository misses keep their status semantics")
            {
                REQUIRE(unauthenticated_upload.status == 401U);
                REQUIRE(unauthenticated_upload.body == "unauthenticated");
                REQUIRE(missing_release.status == 404U);
                REQUIRE(missing_release.body == "media not found");
                REQUIRE(unauthenticated_quarantine.status == 401U);
                REQUIRE(unauthenticated_quarantine.body == "admin authentication required");
            }
        }
    }
}

// --- 0.12.13 security audit, M05 --------------------------------------------

SCENARIO("Legacy unauthenticated media endpoints are frozen for new uploads",
         "[media][repository][integration][security][m05]")
{
    GIVEN("a running homeserver with an authenticated media upload")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        auto const upload = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
        REQUIRE(upload.status == 200U);
        auto const media_id = media_id_from_upload_response(upload.body);

        WHEN("the authenticated v1 download endpoint is used")
        {
            auto const v1_download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});

            THEN("the media is served")
            {
                REQUIRE(v1_download.status == 200U);
                REQUIRE(v1_download.body == "text/plain|hello");
            }
        }

        WHEN("the legacy unauthenticated v3 download and thumbnail endpoints are used")
        {
            auto const v3_download = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/example.org/" + media_id, {}, {}});
            auto const v3_thumbnail = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET",
                          "/_matrix/media/v3/thumbnail/example.org/" + media_id + "?width=32&height=32&method=crop",
                          {},
                          {}});

            THEN("both legacy endpoints fail closed to 404 for post-upgrade uploads")
            {
                REQUIRE(v3_download.status == 404U);
                REQUIRE(v3_download.body == "media not found");
                REQUIRE(v3_thumbnail.status == 404U);
                REQUIRE(v3_thumbnail.body == "thumbnail not found");
            }
        }
    }
}

SCENARIO("Integrated media uploads receive random, non-sequential media IDs",
         "[media][repository][integration][security][m05]")
{
    GIVEN("a running homeserver")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("two small uploads are made")
        {
            auto const first = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hi"});
            auto const second = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|ho"});
            auto const first_id = media_id_from_upload_response(first.body);
            auto const second_id = media_id_from_upload_response(second.body);

            THEN("the media IDs are different and not derived from content or a counter")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(second.status == 200U);
                REQUIRE_FALSE(first_id.empty());
                REQUIRE_FALSE(second_id.empty());
                REQUIRE(first_id != second_id);
                REQUIRE(first_id.size() == 22U);
                REQUIRE(second_id.size() == 22U);
            }
        }
    }
}

SCENARIO("Integrated media repository policy still rejects unsafe remote boundary inputs",
         "[media][security][integration]")
{
    GIVEN("a remote media flow targeting a private address and unsafe decoder")
    {
        auto const remote = merovingian::media::RemoteMediaFetchRequest{
            "media.example.org", "media123", "media.example.org", {"192.168.1.20"}, true, true,
        };
        auto const decoder_policy =
            merovingian::media::DecoderSafetyPolicy{1048576U, 16777216U, 4096000U, 1U, 64U, true};
        auto const decoder = merovingian::media::DecoderSafetyRequest{4096U, 65536U, 65536U, 1U, false};
        auto const admin_action = merovingian::media::AdminQuarantineRequest{
            merovingian::media::AdminQuarantineAction::quarantine,
            "@admin:example.org",
            "media123",
            "remote fetch rejected",
        };

        WHEN("each boundary decision is evaluated")
        {
            auto const remote_decision = merovingian::media::remote_media_fetch_policy(remote);
            auto const decoder_decision = merovingian::media::evaluate_decoder_safety(decoder_policy, decoder);
            auto const admin_decision = merovingian::media::admin_quarantine_policy(admin_action);

            THEN("unsafe remote fetches and decoders fail closed while admin quarantine remains "
                 "available")
            {
                REQUIRE(remote_decision.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(remote_decision.reason == "remote media address is private or loopback");
                REQUIRE(decoder_decision.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(decoder_decision.reason == "decoder is not allowed");
                REQUIRE(admin_decision.disposition == merovingian::media::MediaDisposition::accept);
            }
        }
    }
}
