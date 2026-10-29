// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX CONTENT REPOSITORY CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, "Content repository"             |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#content-repository
// |                                                                         |
// |  Every REQUIRE encodes a MUST or SHOULD from the spec. If one fails,    |
// |  fix the implementation; never weaken the assertion.                    |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto content_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
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

auto const png_bytes = std::string{"\x89PNG\r\n\x1a\nconformance-image"};

[[nodiscard]] auto upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                          std::string const& target) -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", target, token, png_bytes, {merovingian::http::Header{"Content-Type", "image/png"}}});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* content_uri = string_member(body, "content_uri");
    REQUIRE(content_uri != nullptr);
    REQUIRE(content_uri->starts_with("mxc://example.org/"));
    return content_uri->substr(std::string_view{"mxc://example.org/"}.size());
}

[[nodiscard]] auto header_value(merovingian::homeserver::LocalHttpResponse const& response, std::string_view name)
    -> std::optional<std::string>
{
    for (auto const& [header, value] : response.headers)
    {
        if (header == name)
        {
            return value;
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto create(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(runtime,
                                                                 {"POST", "/_matrix/media/v1/create", token, {}});
}

[[nodiscard]] auto created_media_id(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    REQUIRE(result.response.status == 200U);
    auto const body = parse_object(result.response.body);
    auto const* content_uri = string_member(body, "content_uri");
    REQUIRE(content_uri != nullptr);
    REQUIRE(content_uri->starts_with("mxc://example.org/"));
    return content_uri->substr(std::string_view{"mxc://example.org/"}.size());
}

[[nodiscard]] auto put_upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                              std::string const& media_id, std::string const& bytes = png_bytes,
                              std::string const& content_type = "image/png") -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT",
                  "/_matrix/media/v3/upload/example.org/" + media_id,
                  token,
                  bytes,
                  {merovingian::http::Header{"Content-Type", content_type}}});
}

[[nodiscard]] auto download(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                            std::string const& path_and_query) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + path_and_query, token, {}});
}

[[nodiscard]] auto get(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                       std::string const& target) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}});
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/media/download/{serverName}/{mediaId}/{fileName}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaidfilename
//
// Summary: "This will download content from the content repository (same as the
// previous endpoint) but replaces the target file name with the one provided by
// the caller." The 200 response's Content-Disposition "MUST be one of inline or
// attachment, and MUST contain the file name requested in the path".
// (Conformance audit R17: this route returned 404 for media that exists.)
SCENARIO("GET /v1/media/download/{serverName}/{mediaId}/{fileName} serves existing media under that name",
         "[conformance][client-server][media][r17]")
{
    GIVEN("a user who uploaded a PNG")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");
        auto const media_id = upload(started.runtime, token, "/_matrix/media/v3/upload");
        auto const prefix = std::string{"/_matrix/client/v1/media/download/example.org/"};

        WHEN("the media is downloaded by the named route")
        {
            auto const response = get(started.runtime, token, prefix + media_id + "/holiday.png");

            THEN("the uploaded bytes are served with their content type")
            {
                // Spec MUST: 200 with "The content that was previously uploaded".
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == png_bytes);
                // Spec MUST: Content-Type "either exactly the same as the original upload, or reasonably close".
                REQUIRE(header_value(response.response, "Content-Type") == std::optional<std::string>{"image/png"});
            }

            THEN("Content-Disposition names the requested file and is inline for an inline-safe type")
            {
                // Spec MUST: "inline or attachment, and MUST contain the file name requested in the path";
                // SHOULD be inline for a type allowed inline.
                REQUIRE(header_value(response.response, "Content-Disposition") ==
                        std::optional<std::string>{R"(inline; filename="holiday.png")"});
            }
        }

        WHEN("the named route carries a percent-encoded non-ASCII file name")
        {
            auto const response = get(started.runtime, token, prefix + media_id + "/caf%C3%A9.png");

            THEN("the name is given in the RFC 5987 extended form")
            {
                // Spec MUST: Content-Disposition contains the file name requested in the path.
                REQUIRE(response.response.status == 200U);
                REQUIRE(header_value(response.response, "Content-Disposition") ==
                        std::optional<std::string>{"inline; filename*=utf-8''caf%C3%A9.png"});
            }
        }

        WHEN("the named route carries a query string")
        {
            auto const response =
                get(started.runtime, token, prefix + media_id + "/holiday.png?allow_redirect=false&timeout_ms=10");

            THEN("the query is not part of the file name")
            {
                // Spec MUST: the file name is the path's {fileName}; allow_redirect and timeout_ms are query
                // parameters.
                REQUIRE(response.response.status == 200U);
                REQUIRE(header_value(response.response, "Content-Disposition") ==
                        std::optional<std::string>{R"(inline; filename="holiday.png")"});
            }
        }

        WHEN("the named route asks for media that does not exist")
        {
            auto const response = get(started.runtime, token, prefix + "doesnotexist/file.txt");

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 "The content could not be found", errcode M_NOT_FOUND.
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
            }
        }

        WHEN("the route has a segment after the file name")
        {
            auto const response = get(started.runtime, token, prefix + media_id + "/holiday.png/extra");

            THEN("it is not a download route")
            {
                // Spec MUST: {fileName} is one path segment; nothing else matches the route.
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("the named route is called without an access token")
        {
            auto const response = get(started.runtime, {}, prefix + media_id + "/holiday.png");

            THEN("it is refused like the other authenticated media routes")
            {
                // Spec MUST: "Requires authentication: Yes"; 401 M_MISSING_TOKEN without a token.
                REQUIRE(response.response.status == 401U);
                REQUIRE(errcode_of(response) == "M_MISSING_TOKEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/media/v3/download/{serverName}/{mediaId}/{fileName} (deprecated)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixmediav3downloadservernamemediaidfilename
//
// Summary: the deprecated route has the same contract: Content-Disposition
// "MUST contain the file name requested in the path". Section "Content
// repository": servers SHOULD "freeze" the deprecated unauthenticated endpoints,
// and media uploaded after the freeze "SHOULD only be accessible via the new,
// authenticated, endpoints" (ADR-0068). The named route is frozen exactly as the
// unnamed one is.
SCENARIO("GET /media/v3/download/{serverName}/{mediaId}/{fileName} names pre-freeze media and hides new media",
         "[conformance][client-server][media][r17]")
{
    GIVEN("a user who uploaded a PNG after the freeze")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "bob");
        auto const media_id = upload(started.runtime, token, "/_matrix/media/v3/upload");
        auto const target = "/_matrix/media/v3/download/example.org/" + media_id + "/notes.png";

        WHEN("the media is downloaded by the deprecated named route")
        {
            auto const response = get(started.runtime, {}, target);

            THEN("it is not served there, as by the unnamed deprecated route")
            {
                // Spec SHOULD: media uploaded after the freeze is only accessible via the authenticated endpoints.
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
            }
        }

        AND_GIVEN("the media predates the freeze")
        {
            auto& records = started.runtime.homeserver.media_repository.records;
            auto const record = std::ranges::find_if(records, [&media_id](auto const& current) {
                return current.media_id == media_id;
            });
            // Fixture: the upload's record exists, so it can be marked as predating the freeze.
            REQUIRE(record != records.end());
            record->legacy_endpoint_visible = true;

            WHEN("it is downloaded by the deprecated named route")
            {
                auto const response = get(started.runtime, {}, target);

                THEN("the bytes are served and Content-Disposition names the requested file")
                {
                    // Spec MUST: 200 with the content, and Content-Disposition contains the requested file name.
                    REQUIRE(response.response.status == 200U);
                    REQUIRE(response.response.body == png_bytes);
                    REQUIRE(header_value(response.response, "Content-Disposition") ==
                            std::optional<std::string>{R"(inline; filename="notes.png")"});
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Content repository (the freeze of the deprecated media endpoints)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#content-repository
//
// Summary: media uploaded after the freeze "SHOULD only be accessible via the
// new, authenticated, endpoints", and remote media the server "had to
// re-download" during the freeze counts as media from after the freeze (ADR-0068). So
// the deprecated routes serve a remote copy only when it was cached before the
// freeze, and never fetch one: the fetch would itself make it post-freeze media.
SCENARIO("The deprecated media routes serve only remote media cached before the freeze, and never fetch",
         "[conformance][client-server][media][freeze]")
{
    GIVEN("a server that fetches remote media, holding a copy of remote.example.org's media cached during the freeze")
    {
        auto config = content_config();
        config.security().media.remote_fetch_enabled = true;
        config.security().media.remote_fetch_media_policy = "allow";
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "carol");
        auto const local_id = upload(started.runtime, token, "/_matrix/client/v1/media/upload");
        auto& repository = started.runtime.homeserver.media_repository;
        auto const record = std::ranges::find_if(repository.records, [&local_id](auto const& current) {
            return current.media_id == local_id;
        });
        // Fixture: the stored copy exists, so it can stand for a cached remote file.
        REQUIRE(record != repository.records.end());
        record->from_remote_fetch = true;
        auto const now = merovingian::media::remote_media_cache_now_ms();
        repository.remote_media_cache.push_back(
            {"remote.example.org", "cachedRemote", local_id, now + 3'600'000U, now});

        WHEN("the cached remote media is downloaded or thumbnailed by the deprecated routes")
        {
            auto const download =
                get(started.runtime, {}, "/_matrix/media/v3/download/remote.example.org/cachedRemote");
            auto const thumbnail = get(started.runtime, {},
                                       "/_matrix/media/v3/thumbnail/remote.example.org/cachedRemote"
                                       "?width=32&height=32&method=scale");

            THEN("neither serves it")
            {
                // Spec SHOULD: media re-downloaded during the freeze is new, so only the authenticated endpoints serve
                // it.
                REQUIRE(download.response.status == 404U);
                REQUIRE(errcode_of(download) == "M_NOT_FOUND");
                REQUIRE(thumbnail.response.status == 404U);
                REQUIRE(errcode_of(thumbnail) == "M_NOT_FOUND");
            }
        }

        WHEN("remote media this server does not hold is asked for by the deprecated download route")
        {
            auto const response = get(started.runtime, {}, "/_matrix/media/v3/download/remote.example.org/notCached");

            THEN("it is refused at once, without fetching it")
            {
                // Spec SHOULD: a fetch now would make it post-freeze media, which the deprecated endpoints do not
                // serve.
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
                REQUIRE(repository.remote_media_cache.size() == 1U);
            }
        }

        WHEN("the cached remote media is downloaded by the authenticated route")
        {
            auto const response =
                get(started.runtime, token, "/_matrix/client/v1/media/download/remote.example.org/cachedRemote");

            THEN("it is served")
            {
                // Spec SHOULD: post-freeze media stays accessible via the authenticated endpoints.
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == png_bytes);
            }
        }

        AND_GIVEN("the copy was cached before the freeze")
        {
            record->legacy_endpoint_visible = true;

            WHEN("it is downloaded by the deprecated route")
            {
                auto const response =
                    get(started.runtime, {}, "/_matrix/media/v3/download/remote.example.org/cachedRemote");

                THEN("it is served there, like local media uploaded before the freeze")
                {
                    // Spec SHOULD: media from before the freeze remains accessible via the deprecated endpoints.
                    REQUIRE(response.response.status == 200U);
                    REQUIRE(response.response.body == png_bytes);
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/media/download/{serverName}/{mediaId}, 200 response headers
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
//
// Summary: Content-Disposition "If the upload was made with a filename, this
// header MUST contain the same filename. Otherwise, filename is excluded from
// the header."
SCENARIO("Downloads give back the filename the upload was made with", "[conformance][client-server][media][r17]")
{
    GIVEN("one upload made with ?filename= and one made without")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");
        auto const named = upload(started.runtime, token, "/_matrix/media/v3/upload?filename=cat%20photo.png");
        auto const unnamed = upload(started.runtime, token, "/_matrix/client/v1/media/upload");

        WHEN("both are downloaded by the two-segment route")
        {
            auto const with_name = download(started.runtime, token, named);
            auto const without_name = download(started.runtime, token, unnamed);

            THEN("the named upload's Content-Disposition contains the same filename")
            {
                // Spec MUST: "this header MUST contain the same filename".
                REQUIRE(with_name.response.status == 200U);
                REQUIRE(header_value(with_name.response, "Content-Disposition") ==
                        std::optional<std::string>{R"(inline; filename="cat photo.png")"});
            }

            THEN("the unnamed upload's Content-Disposition carries no filename")
            {
                // Spec: "Otherwise, filename is excluded from the header."
                REQUIRE(without_name.response.status == 200U);
                REQUIRE(header_value(without_name.response, "Content-Disposition") ==
                        std::optional<std::string>{"inline"});
            }
        }

        WHEN("the named upload is downloaded by the {fileName} route")
        {
            auto const renamed = download(started.runtime, token, named + "/renamed.png");

            THEN("the caller's file name replaces the upload's")
            {
                // Spec MUST: the {fileName} route serves the content and its Content-Disposition "MUST contain
                // the file name requested in the path", not the upload's filename.
                REQUIRE(renamed.response.status == 200U);
                REQUIRE(header_value(renamed.response, "Content-Disposition") ==
                        std::optional<std::string>{R"(inline; filename="renamed.png")"});
            }
        }
    }

    GIVEN("an upload whose filename carries a control character")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");

        WHEN("it is uploaded")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST",
                                  "/_matrix/media/v3/upload?filename=evil%0D%0AX-Injected:%201.png",
                                  token,
                                  png_bytes,
                                  {merovingian::http::Header{"Content-Type", "image/png"}}});

            THEN("it is refused, so no header can be injected through it")
            {
                // Project policy: an unsafe filename is refused, so the stored name is the one sent (ADR-0211);
                // M_INVALID_PARAM is "A parameter that was specified has the wrong value".
                REQUIRE(response.response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/media/v1/create
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixmediav1create
//
// Summary: "Creates a new mxc:// URI, independently of the content being
// uploaded." 200: content_uri (Required) and unused_expires_at, "the maximum
// POSIX millisecond timestamp to complete the upload"; "The recommended default
// expiration is 24 hours". "the server should limit the number of concurrent
// pending media uploads a given user can have ... respond with an HTTP 429
// error with an errcode of M_LIMIT_EXCEEDED."
SCENARIO("POST /media/v1/create reserves an mxc:// URI that expires",
         "[conformance][client-server][media][async-upload]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");

        WHEN("an mxc:// URI is created")
        {
            auto const before_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
            auto const response = create(started.runtime, token);

            THEN("the response names a URI on this server and an expiry about 24 hours away")
            {
                // Spec MUST: content_uri is required.
                auto const media_id = created_media_id(response);
                // Spec MUST: content_uri is "Required".
                REQUIRE_FALSE(media_id.empty());
                auto const body = parse_object(response.response.body);
                auto const* expires = int_member(body, "unused_expires_at");
                // Spec MUST: unused_expires_at, the time "the generated media id will expire, if media is not
                // uploaded".
                REQUIRE(expires != nullptr);
                // Spec SHOULD: the recommended default expiration is 24 hours.
                auto const day_ms = std::int64_t{24} * 60 * 60 * 1000;
                REQUIRE(*expires >= before_ms + day_ms - 60000);
                REQUIRE(*expires <= before_ms + day_ms + 60000);
            }
        }

        WHEN("the user creates more URIs than the per-user pending limit allows")
        {
            started.runtime.homeserver.media_repository.config.max_pending_uploads_per_user = 2U;
            auto const first = create(started.runtime, token);
            auto const second = create(started.runtime, token);
            auto const third = create(started.runtime, token);

            THEN("the one past the limit is refused with 429 M_LIMIT_EXCEEDED")
            {
                // Spec SHOULD: the server "should limit the number of concurrent pending media uploads"; below the
                // limit, create succeeds.
                REQUIRE(first.response.status == 200U);
                REQUIRE(second.response.status == 200U);
                // Spec SHOULD: 429 M_LIMIT_EXCEEDED for too many pending uploads.
                REQUIRE(third.response.status == 429U);
                REQUIRE(errcode_of(third) == "M_LIMIT_EXCEEDED");
            }

            AND_WHEN("one of the pending uploads is completed")
            {
                // Spec MUST: PUT /upload/{serverName}/{mediaId} answers 200 "The upload was successful".
                REQUIRE(put_upload(started.runtime, token, created_media_id(first)).response.status == 200U);
                auto const after = create(started.runtime, token);

                THEN("a completed upload is no longer pending, so another URI can be created")
                {
                    // Spec SHOULD: a pending upload is a URI "where (a) the media has not yet been uploaded", so a
                    // completed one no longer counts.
                    REQUIRE(after.response.status == 200U);
                }
            }
        }

        WHEN("the request carries no access token")
        {
            auto const response = create(started.runtime, {});

            THEN("the request is refused as unauthenticated")
            {
                // Spec MUST: "Requires authentication: Yes"; missing credentials return 401.
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/media/v3/upload/{serverName}/{mediaId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixmediav3uploadservernamemediaid
//
// Summary: 200 {} on success; 403 M_FORBIDDEN when "The request comes from a
// different user than the one that called POST /_matrix/media/v1/create"; 404
// M_NOT_FOUND when "The MXC ID was not created with POST
// /_matrix/media/v1/create" or "The MXC ID has expired"; 409
// M_CANNOT_OVERWRITE_MEDIA when "called with a media ID that already has
// content"; 413 when "The uploaded content is too large for the server"; 403
// when "The server does not permit the file type".
SCENARIO("PUT /media/v3/upload/{serverName}/{mediaId} fills a reserved URI exactly once",
         "[conformance][client-server][media][async-upload]")
{
    GIVEN("alice has reserved an mxc:// URI and bob is another user")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");
        auto const bob = login(started.runtime, "bob");
        auto const media_id = created_media_id(create(started.runtime, alice));

        WHEN("alice uploads the content")
        {
            auto const response = put_upload(started.runtime, alice, media_id);

            THEN("it succeeds with an empty object and the content is downloadable at the reserved URI")
            {
                // Spec MUST: 200 {}.
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
                auto const downloaded = download(started.runtime, alice, media_id);
                // Spec MUST: the uploaded content is served at the reserved URI.
                REQUIRE(downloaded.response.status == 200U);
                REQUIRE(downloaded.response.body == png_bytes);
            }

            AND_WHEN("alice uploads to the same URI again")
            {
                auto const again = put_upload(started.runtime, alice, media_id);

                THEN("the server refuses to overwrite it with 409 M_CANNOT_OVERWRITE_MEDIA")
                {
                    // Spec MUST: 409 M_CANNOT_OVERWRITE_MEDIA, "a media ID that already has content".
                    REQUIRE(again.response.status == 409U);
                    REQUIRE(errcode_of(again) == "M_CANNOT_OVERWRITE_MEDIA");
                }
            }

            AND_WHEN("alice uploads an empty body to the same URI")
            {
                auto const again = put_upload(started.runtime, alice, media_id, std::string{}, "image/png");

                THEN("the server refuses to overwrite it with 409 M_CANNOT_OVERWRITE_MEDIA, whatever the body")
                {
                    // Spec MUST: 409 M_CANNOT_OVERWRITE_MEDIA, "a media ID that already has content"; the media ID,
                    // not the request body, decides the answer.
                    REQUIRE(again.response.status == 409U);
                    REQUIRE(errcode_of(again) == "M_CANNOT_OVERWRITE_MEDIA");
                }
            }

            AND_WHEN("alice uploads different content with no Content-Type to the same URI")
            {
                auto const again = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"PUT", "/_matrix/media/v3/upload/example.org/" + media_id, alice, "other bytes"});

                THEN("the server refuses to overwrite it with 409 M_CANNOT_OVERWRITE_MEDIA")
                {
                    // Spec MUST: 409 M_CANNOT_OVERWRITE_MEDIA, "a media ID that already has content".
                    REQUIRE(again.response.status == 409U);
                    REQUIRE(errcode_of(again) == "M_CANNOT_OVERWRITE_MEDIA");
                    // Spec MUST: the first upload's content is still served at the URI.
                    REQUIRE(download(started.runtime, alice, media_id).response.body == png_bytes);
                }
            }
        }

        WHEN("bob uploads to alice's reserved URI")
        {
            auto const response = put_upload(started.runtime, bob, media_id);

            THEN("it is refused with 403 M_FORBIDDEN, and alice can still upload to it")
            {
                // Spec MUST: 403 M_FORBIDDEN when "The request comes from a different user than the one that
                // called POST /_matrix/media/v1/create".
                REQUIRE(response.response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                // Spec MUST: nothing was stored, or alice's upload would be 409 M_CANNOT_OVERWRITE_MEDIA ("a
                // media ID that already has content").
                REQUIRE(put_upload(started.runtime, alice, media_id).response.status == 200U);
            }
        }

        WHEN("alice uploads to a media ID that was never created")
        {
            auto const response = put_upload(started.runtime, alice, "neverCreatedMediaId00");

            THEN("it is refused with 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 M_NOT_FOUND, "The user has provided an invalid MXC ID" (not created with POST
                // /create).
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
            }
        }

        WHEN("alice uploads to the reserved ID under another server's name")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT",
                                  "/_matrix/media/v3/upload/other.example.org/" + media_id,
                                  alice,
                                  png_bytes,
                                  {merovingian::http::Header{"Content-Type", "image/png"}}});

            THEN("it is refused with 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 M_NOT_FOUND, "The user has provided an invalid MXC ID" (not created with POST
                // /create).
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
            }
        }

        WHEN("the reservation has expired before alice uploads")
        {
            started.runtime.homeserver.media_repository.pending_uploads.at(media_id).expires_at_ms = 1U;
            auto const response = put_upload(started.runtime, alice, media_id);

            THEN("it is refused with 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when "The MXC ID has expired".
                REQUIRE(response.response.status == 404U);
                REQUIRE(errcode_of(response) == "M_NOT_FOUND");
            }
        }

        WHEN("alice uploads more than max_upload_size")
        {
            started.runtime.homeserver.media_repository.config.max_upload_bytes = 4U;
            auto const response = put_upload(started.runtime, alice, media_id);

            THEN("it is refused with 413 M_TOO_LARGE and the URI stays reserved without content")
            {
                // Spec MUST: 413 M_TOO_LARGE, "The uploaded content is too large for the server".
                REQUIRE(response.response.status == 413U);
                REQUIRE(errcode_of(response) == "M_TOO_LARGE");
                // Spec MUST: a reserved URI without content downloads as 504 M_NOT_YET_UPLOADED, "The content is
                // not yet available"; an unknown or expired one would be 404.
                auto const downloaded = download(started.runtime, alice, media_id + "?timeout_ms=0");
                REQUIRE(downloaded.response.status == 504U);
                REQUIRE(errcode_of(downloaded) == "M_NOT_YET_UPLOADED");
            }
        }

        WHEN("alice uploads a file type the server does not permit")
        {
            started.runtime.homeserver.media_repository.config.quarantine_unknown_mime = false;
            started.runtime.homeserver.media_repository.config.allowed_mime_types = {"image/png"};
            auto const response = put_upload(started.runtime, alice, media_id, "plain words\n", "text/plain");

            THEN("it is refused with 403 M_FORBIDDEN")
            {
                // Spec MUST: 403 M_FORBIDDEN, "The server does not permit the file type".
                REQUIRE(response.response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/media/download/{serverName}/{mediaId}, 200 response headers
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
//
// Summary: Content-Disposition "If the upload was made with a filename, this
// header MUST contain the same filename." A remote server downloads our media
// through the federation endpoint, so the filename the upload was made with
// must reach that endpoint's answer, or the remote server cannot serve it.
SCENARIO("The federation media provider gives the filename the upload was made with",
         "[conformance][client-server][media][federation][r17]")
{
    GIVEN("an upload made with a Unicode filename and one made without a filename")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");
        auto const named = upload(started.runtime, token, "/_matrix/media/v3/upload?filename=%F0%9F%90%94");
        auto const unnamed = upload(started.runtime, token, "/_matrix/media/v3/upload");

        WHEN("a remote server's download is answered for each")
        {
            auto const with_name =
                merovingian::homeserver::download_local_media_for_federation(started.runtime.homeserver, named);
            auto const without_name =
                merovingian::homeserver::download_local_media_for_federation(started.runtime.homeserver, unnamed);

            THEN("the first carries the filename and the second none")
            {
                // Spec MUST: "this header MUST contain the same filename"; "Otherwise, filename is excluded".
                REQUIRE(with_name.ok);
                REQUIRE(with_name.upload_name == "\xF0\x9F\x90\x94");
                REQUIRE(without_name.ok);
                REQUIRE(without_name.upload_name.empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/media/download/{serverName}/{mediaId}, 200 Content-Type
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
//
// Summary: the 200 response's Content-Type is "The content type of the file that
// was previously uploaded", so an upload made with Content-Type img/png is given
// back as img/png. Project policy (owner decision 2026-10-29): a
// declared type that is a spelling variant of the sniffed one (letter case, or
// the misspelt top-level type img for image) is not a mismatch, so the upload is
// not quarantined; any other mismatch still is.
SCENARIO("An upload whose declared type is a spelling variant of its content type is served as declared",
         "[conformance][client-server][media][mime-equivalence]")
{
    GIVEN("alice uploads a PNG declared as img/png, once with POST and once into a reserved URI with PUT")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");
        auto const posted = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST",
                              "/_matrix/media/v3/upload",
                              alice,
                              png_bytes,
                              {merovingian::http::Header{"Content-Type", "img/png"}}});
        // Spec MUST: 200 with a content_uri for an accepted upload.
        REQUIRE(posted.response.status == 200U);
        auto const posted_body = parse_object(posted.response.body);
        auto const* posted_uri = string_member(posted_body, "content_uri");
        REQUIRE(posted_uri != nullptr);
        auto const posted_id = posted_uri->substr(std::string_view{"mxc://example.org/"}.size());
        auto const reserved_id = created_media_id(create(started.runtime, alice));
        REQUIRE(put_upload(started.runtime, alice, reserved_id, png_bytes, "img/png").response.status == 200U);

        WHEN("each is downloaded")
        {
            auto const from_post = download(started.runtime, alice, posted_id);
            auto const from_put = download(started.runtime, alice, reserved_id);

            THEN("both are served, not held as quarantined")
            {
                // Spec MUST: 200 "The content that was previously uploaded".
                REQUIRE(from_post.response.status == 200U);
                REQUIRE(from_post.response.body == png_bytes);
                REQUIRE(from_put.response.status == 200U);
                REQUIRE(from_put.response.body == png_bytes);
            }

            THEN("the Content-Type is the one the upload declared")
            {
                // Spec MUST: Content-Type is "The content type of the file that was previously uploaded".
                REQUIRE(header_value(from_post.response, "Content-Type") == std::optional<std::string>{"img/png"});
                REQUIRE(header_value(from_put.response, "Content-Type") == std::optional<std::string>{"img/png"});
            }

            THEN("the safe response headers are still sent")
            {
                // Project policy: nosniff on every response, so a browser never second-guesses the type.
                REQUIRE(header_value(from_post.response, "X-Content-Type-Options") ==
                        std::optional<std::string>{"nosniff"});
            }
        }
    }

    GIVEN("uploads whose declared type is not equivalent to their content")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");

        WHEN("a PNG is declared as img/jpeg or as text/html")
        {
            auto const upload_declared = [&](std::string const& declared) {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/media/v3/upload",
                                      alice,
                                      png_bytes,
                                      {merovingian::http::Header{"Content-Type", declared}}});
                // Project policy: a held upload still answers 200 with a content_uri.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* uri = string_member(body, "content_uri");
                REQUIRE(uri != nullptr);
                return download(started.runtime, alice, uri->substr(std::string_view{"mxc://example.org/"}.size()));
            };
            auto const jpeg = upload_declared("img/jpeg");
            auto const html = upload_declared("text/html");

            THEN("both are still quarantined, so a download is answered 451")
            {
                // Project policy: a declared type that does not match the content is held for review.
                REQUIRE(jpeg.response.status == 451U);
                REQUIRE(html.response.status == 451U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/media/download/{serverName}/{mediaId}, timeout_ms and 504
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
//
// Summary: timeout_ms is "The maximum number of milliseconds that the client is
// willing to wait to start receiving data, in the case that the content has not
// yet been uploaded ... The content repository SHOULD impose a maximum value for
// this parameter. The content repository MAY respond before the timeout." 504:
// "The content is not yet available. A standard error response will be returned
// with the errcode M_NOT_YET_UPLOADED."
SCENARIO("Downloading reserved media before its upload waits up to timeout_ms, then answers 504",
         "[conformance][client-server][media][async-upload]")
{
    GIVEN("alice has reserved an mxc:// URI and not uploaded to it")
    {
        auto started = merovingian::homeserver::start_client_server(content_config());
        // Fixture: the server starts.
        REQUIRE(started.started);
        auto const alice = login(started.runtime, "alice");
        auto const media_id = created_media_id(create(started.runtime, alice));

        WHEN("it is downloaded with timeout_ms=0")
        {
            auto const response = download(started.runtime, alice, media_id + "?timeout_ms=0");

            THEN("the server answers 504 M_NOT_YET_UPLOADED")
            {
                // Spec MUST: 504 M_NOT_YET_UPLOADED, "The content is not yet available" (timeout_ms=0 waits for
                // nothing).
                REQUIRE(response.response.status == 504U);
                REQUIRE(errcode_of(response) == "M_NOT_YET_UPLOADED");
            }
        }

        WHEN("it is downloaded with a short timeout and nothing is uploaded")
        {
            auto const started_at = std::chrono::steady_clock::now();
            auto const response = download(started.runtime, alice, media_id + "?timeout_ms=150");
            auto const waited = std::chrono::steady_clock::now() - started_at;

            THEN("the server waits about that long and then answers 504 M_NOT_YET_UPLOADED")
            {
                // Spec MUST: 504 M_NOT_YET_UPLOADED, "The content is not yet available". Project policy: the server
                // waits up to timeout_ms, how long the client "is willing to wait", before answering.
                REQUIRE(response.response.status == 504U);
                REQUIRE(errcode_of(response) == "M_NOT_YET_UPLOADED");
                REQUIRE(waited >= std::chrono::milliseconds{100});
            }
        }

        WHEN("the client asks to wait longer than the server's maximum")
        {
            started.runtime.homeserver.media_repository.config.pending_upload_max_wait_ms = 50U;
            auto const started_at = std::chrono::steady_clock::now();
            auto const response = download(started.runtime, alice, media_id + "?timeout_ms=60000");
            auto const waited = std::chrono::steady_clock::now() - started_at;

            THEN("the server's maximum bounds the wait")
            {
                // Spec SHOULD: impose a maximum value for timeout_ms.
                REQUIRE(response.response.status == 504U);
                REQUIRE(waited < std::chrono::seconds{10});
            }
        }

        WHEN("it is uploaded while a download is waiting")
        {
            auto waiter_status = std::uint16_t{0U};
            auto waiter_body = std::string{};
            auto threads = merovingian::tests::JoiningThreads{};
            threads.emplace_back([&started, &alice, &media_id, &waiter_status, &waiter_body] {
                auto const response = download(started.runtime, alice, media_id + "?timeout_ms=10000");
                waiter_status = response.response.status;
                waiter_body = response.response.body;
            });
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (started.runtime.homeserver.media_upload_notifier->waiting() == 0U &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            }
            auto const uploaded = put_upload(started.runtime, alice, media_id);
            threads.join();

            THEN("the waiting download is served the content")
            {
                // Spec MUST: content uploaded during the wait is served to the waiting download.
                REQUIRE(uploaded.response.status == 200U);
                REQUIRE(waiter_status == 200U);
                REQUIRE(waiter_body == png_bytes);
            }
        }

        WHEN("a remote server asks for it over federation")
        {
            auto const result =
                merovingian::homeserver::download_local_media_for_federation(started.runtime.homeserver, media_id);

            THEN("it is answered 504 at once, since the federation path has no pool to wait on")
            {
                // Project policy: the federation route has no pool to wait on and answers 504 at once, which the
                // spec allows ("The content repository MAY respond before the timeout").
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 504U);
            }
        }
    }
}
