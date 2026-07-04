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
