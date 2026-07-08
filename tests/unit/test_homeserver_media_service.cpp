// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/media_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// Security audit finding: fetch_remote_media_live() built the outbound
// federation media download URL as /_matrix/media/v3/download/{mediaId},
// omitting the {serverName} segment the spec requires
// (server-server-api.md#get_matrixmediav3downloadservernamemediaid) and never
// percent-encoding either segment. remote_media_download_url() is the
// extracted, unit-testable pure function backing that URL construction.
SCENARIO("remote_media_download_url builds the spec-shaped, percent-encoded federation media download URL",
         "[homeserver][media][security]")
{
    GIVEN("a resolved host/port, an origin server name, and a media ID")
    {
        WHEN("the URL is built for ordinary inputs")
        {
            auto const url = merovingian::homeserver::remote_media_download_url("matrix.example.org", 8448U,
                                                                                "remote.example.org", "abc123");

            THEN("both the server name and media ID appear as their own path segments")
            {
                REQUIRE(url == "https://matrix.example.org:8448/_matrix/media/v3/download/remote.example.org/abc123");
            }
        }

        WHEN("the origin server name or media ID contains reserved URL characters")
        {
            auto const url = merovingian::homeserver::remote_media_download_url("matrix.example.org", 8448U,
                                                                                "remote.example.org", "abc/../123?x=1");

            THEN("the reserved characters are percent-encoded rather than forming extra path segments")
            {
                REQUIRE(url.find("/_matrix/media/v3/download/remote.example.org/") != std::string::npos);
                // A literal '/' or '?' in the decoded media ID must not survive
                // into the URL as a path or query separator.
                auto const media_segment =
                    url.substr(url.find("/_matrix/media/v3/download/remote.example.org/") +
                               std::string{"/_matrix/media/v3/download/remote.example.org/"}.size());
                REQUIRE(media_segment.find('/') == std::string::npos);
                REQUIRE(media_segment.find('?') == std::string::npos);
            }
        }
    }
}

// Federated attachment download bug: fetch_remote_media_live() called only the
// deprecated /_matrix/media/v3/download/{serverName}/{mediaId} endpoint, which
// current Synapse and Merovingian deployments disable by default (spec change
// in v1.11: server-server-api.md#content-repository). Every remote fetch 404'd
// as a result. remote_federation_media_download_url() builds the mandatory
// authenticated endpoint that must be tried first.
SCENARIO("remote_federation_media_download_url builds the authenticated federation media download URL",
         "[homeserver][media][federation]")
{
    GIVEN("a resolved host/port and a media ID")
    {
        WHEN("the URL is built for ordinary inputs")
        {
            auto const url =
                merovingian::homeserver::remote_federation_media_download_url("matrix.example.org", 8448U, "abc123");

            THEN("it targets the v1.11 authenticated endpoint with no serverName path segment")
            {
                REQUIRE(url == "https://matrix.example.org:8448/_matrix/federation/v1/media/download/abc123");
            }
        }

        WHEN("the media ID contains reserved URL characters")
        {
            auto const url = merovingian::homeserver::remote_federation_media_download_url("matrix.example.org", 8448U,
                                                                                           "abc/../123?x=1");

            THEN("the reserved characters are percent-encoded rather than forming extra path segments or a query")
            {
                auto constexpr prefix =
                    std::string_view{"https://matrix.example.org:8448/_matrix/federation/v1/media/download/"};
                REQUIRE(url.rfind(prefix, 0) == 0);
                auto const media_segment = url.substr(prefix.size());
                REQUIRE(media_segment.find('/') == std::string::npos);
                REQUIRE(media_segment.find('?') == std::string::npos);
            }
        }
    }
}

SCENARIO("parse_federation_media_multipart parses the multipart/mixed body of the authenticated media endpoint",
         "[homeserver][media][federation]")
{
    GIVEN("a well-formed two-part multipart response carrying inline media bytes")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "Content-Disposition: inline; filename=\"test.png\"\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the media part's content type and bytes are extracted, and it is not a redirect")
            {
                REQUIRE(parsed.ok);
                REQUIRE_FALSE(parsed.is_redirect);
                REQUIRE(parsed.content_type == "image/png");
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a well-formed response whose second part is a Location redirect instead of inline bytes")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=\"xyz\""};
        auto const body = std::string{"--xyz\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--xyz\r\n"
                                      "Location: https://cdn.example.org/media/abc123\r\n"
                                      "\r\n"
                                      "--xyz--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("it is reported as a redirect carrying the Location URL")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.is_redirect);
                REQUIRE(parsed.location == "https://cdn.example.org/media/abc123");
            }
        }
    }

    GIVEN("a response whose Content-Type header carries no boundary parameter")
    {
        auto const content_type = std::string{"multipart/mixed"};
        auto const body = std::string{"--abc123\r\n\r\n{}\r\n--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("parsing fails rather than misinterpreting the body")
            {
                REQUIRE_FALSE(parsed.ok);
            }
        }
    }

    GIVEN("a response with only one multipart part instead of the mandatory two")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\nContent-Type: application/json\r\n\r\n{}\r\n--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("parsing fails since the media part is missing")
            {
                REQUIRE_FALSE(parsed.ok);
            }
        }
    }
}
