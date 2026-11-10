// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/MediaService.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Content Repository — GET /_matrix/federation/v1/media/download/{mediaId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1mediadownloadmediaid
//
// Summary: "Changed in v1.11: Servers were previously advised to use the
// /_matrix/media/* endpoints ... however, those endpoints have been
// deprecated. New endpoints are introduced which require authentication.
// ... servers MUST try the endpoints described below before falling back to
// the deprecated /_matrix/media/* endpoints when they receive a 404
// M_UNRECOGNIZED error." The mediaId (not the serverName) is the only path
// parameter — the destination server is implied by the request target.
SCENARIO("remote_federation_media_download_url targets the mandatory authenticated media endpoint",
         "[federation][media][conformance]")
{
    GIVEN("a resolved federation host/port and a media ID from an mxc:// URI")
    {
        WHEN("the download URL is built")
        {
            auto const url =
                merovingian::homeserver::remote_federation_media_download_url("matrix.example.org", 8448U, "abc123");

            THEN("it targets /_matrix/federation/v1/media/download/{mediaId} with no serverName path segment")
            {
                // Spec MUST: the endpoint path is /_matrix/federation/v1/media/download/{mediaId}.
                REQUIRE(url == "https://matrix.example.org:8448/_matrix/federation/v1/media/download/abc123");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Content Repository — GET /_matrix/federation/v1/media/download/{mediaId}, 200 response
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1mediadownloadmediaid
//
// Summary: "Content-Type: Must be multipart/mixed ... MUST contain a boundary
// ... delineating exactly two parts: The first part has a Content-Type header
// of application/json and describes the media's metadata ... The second part
// is either: 1. the bytes of the media itself, using Content-Type and
// Content-Disposition headers as appropriate; 2. or a Location header to
// redirect the caller to where the media can be retrieved."
SCENARIO("parse_federation_media_multipart decodes the mandatory two-part multipart/mixed response",
         "[federation][media][conformance]")
{
    GIVEN("a 200 response whose second part carries the media bytes inline")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=boundary123"};
        auto const body = std::string{"--boundary123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--boundary123\r\n"
                                      "Content-Type: image/jpeg\r\n"
                                      "Content-Disposition: inline; filename=\"photo.jpg\"\r\n"
                                      "\r\n"
                                      "JPEGBYTES\r\n"
                                      "--boundary123--\r\n"};

        WHEN("the response is decoded")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the second part's Content-Type and bytes are surfaced, not treated as a redirect")
            {
                // Spec MUST: exactly two parts are present and parseable.
                REQUIRE(parsed.ok);
                // Spec MUST: the second part carries media bytes when no Location header is present.
                REQUIRE_FALSE(parsed.is_redirect);
                REQUIRE(parsed.content_type == "image/jpeg");
                REQUIRE(parsed.bytes == "JPEGBYTES");
            }
        }
    }

    GIVEN("a 200 response whose second part redirects via a Location header instead of inline bytes")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=boundary123"};
        auto const body = std::string{"--boundary123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--boundary123\r\n"
                                      "Location: https://cdn.example.org/abc123\r\n"
                                      "\r\n"
                                      "--boundary123--\r\n"};

        WHEN("the response is decoded")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the redirect is surfaced rather than mistaken for empty media bytes")
            {
                // Spec MUST: a Location header in the second part is a valid alternative to inline bytes.
                REQUIRE(parsed.ok);
                REQUIRE(parsed.is_redirect);
                REQUIRE(parsed.location == "https://cdn.example.org/abc123");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Content Repository - GET /_matrix/federation/v1/media/download/{mediaId}, 200 response
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1mediadownloadmediaid
//
// Summary: the body "delineat[es] exactly two parts". The remote chooses the body, and the parse runs under
// runtime.mutex, so a body of many delimiters must be refused as soon as a third part appears, with work that does not
// grow with the number of delimiters (F-15).
SCENARIO("parse_federation_media_multipart stops at a third part", "[federation][media][conformance][f15]")
{
    GIVEN("bodies made of the delimiter line repeated 10 times and 100000 times")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=x"};
        auto const repeated = [](std::size_t count) {
            auto body = std::string{};
            for (auto i = std::size_t{0U}; i < count; ++i)
            {
                body += "--x\n";
            }
            return body;
        };

        WHEN("each is decoded")
        {
            auto const small = merovingian::homeserver::parse_federation_media_multipart(content_type, repeated(10U));
            auto const large =
                merovingian::homeserver::parse_federation_media_multipart(content_type, repeated(100000U));

            THEN("both are refused and the parser examined the same, small number of parts")
            {
                // Spec MUST: exactly two parts; any other count is refused.
                REQUIRE_FALSE(small.ok);
                REQUIRE_FALSE(large.ok);
                // Work must not grow with the delimiter count: the third part is refused before it is parsed, so at
                // most the cap of two parts is parsed.
                REQUIRE(small.parts_parsed <= 2U);
                REQUIRE(large.parts_parsed == small.parts_parsed);
            }
        }
    }

    GIVEN("a body with two parts, and one with three")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=x"};
        auto const two =
            std::string{"--x\nContent-Type: application/json\n\n{}\n--x\nContent-Type: image/png\n\nPNG\n--x--\n"};
        auto const three = std::string{"--x\n\n{}\n--x\n\nA\n--x\n\nB\n--x--\n"};

        WHEN("each is decoded")
        {
            auto const parsed_two = merovingian::homeserver::parse_federation_media_multipart(content_type, two);
            auto const parsed_three = merovingian::homeserver::parse_federation_media_multipart(content_type, three);

            THEN("the two-part body parses and the three-part body is refused")
            {
                // Spec MUST: exactly two parts.
                REQUIRE(parsed_two.ok);
                REQUIRE(parsed_two.bytes == "PNG");
                REQUIRE_FALSE(parsed_three.ok);
            }
        }
    }
}
