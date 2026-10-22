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
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

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

// Uploads png_bytes and returns the media ID of the content_uri.
[[nodiscard]] auto upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/media/v3/upload",
                  token,
                  png_bytes,
                  {merovingian::http::Header{"Content-Type", "image/png"}}});
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
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");
        auto const media_id = upload(started.runtime, token);
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
        REQUIRE(started.started);
        auto const token = login(started.runtime, "bob");
        auto const media_id = upload(started.runtime, token);
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
