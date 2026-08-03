// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/media_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace
{

class FakeDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        auto found = addresses.find(std::string{host});
        if (found == addresses.end())
        {
            return {false, {}, "address not found"};
        }
        return {true, found->second, {}};
    }

    std::unordered_map<std::string, std::vector<std::string>> addresses{};
};

} // namespace

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

    GIVEN("a response whose boundary string also appears inside the media bytes")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "--abc123 appears inside PNGDATA\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the inner boundary string is kept as part of the media bytes")
            {
                REQUIRE(parsed.ok);
                // The trailing CRLF before the next boundary delimiter is RFC
                // 2046 transport padding, not part of the part body.
                REQUIRE(parsed.bytes == "--abc123 appears inside PNGDATA");
            }
        }
    }

    GIVEN("a response with a preamble before the first boundary delimiter")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"This preamble should be ignored.\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the preamble is skipped and the two spec parts are found")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.content_type == "image/png");
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a response using LF-only line endings")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\n"
                                      "Content-Type: application/json\n"
                                      "\n"
                                      "{}\n"
                                      "--abc123\n"
                                      "Content-Type: image/png\n"
                                      "\n"
                                      "PNGDATA\n"
                                      "--abc123--\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the parser tolerates the single-character transport padding")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a response whose boundary parameter contains punctuation from a quoted value")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=\"boundary.with-special\""};
        auto const body = std::string{"--boundary.with-special\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--boundary.with-special\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--boundary.with-special--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the literal boundary value is matched, not treated as a regex")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a response whose boundary parameter has RFC 2046 whitespace around the equals sign")
    {
        auto const content_type = std::string{"multipart/mixed; boundary = \"abc123\""};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the boundary token is extracted and parsing succeeds")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a response whose closing boundary lacks trailing CRLF")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--abc123--"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("parsing still succeeds")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }
    }

    GIVEN("a response with a Location-only second part and no body bytes")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Location: https://cdn.example.org/media/abc123\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("the redirect is still detected")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.is_redirect);
                REQUIRE(parsed.location == "https://cdn.example.org/media/abc123");
            }
        }
    }

    GIVEN("a response containing more than the mandatory two parts")
    {
        auto const content_type = std::string{"multipart/mixed; boundary=abc123"};
        auto const body = std::string{"--abc123\r\n"
                                      "Content-Type: application/json\r\n"
                                      "\r\n"
                                      "{}\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: image/png\r\n"
                                      "\r\n"
                                      "PNGDATA\r\n"
                                      "--abc123\r\n"
                                      "Content-Type: text/plain\r\n"
                                      "\r\n"
                                      "EXTRA\r\n"
                                      "--abc123--\r\n"};

        WHEN("the response is parsed")
        {
            auto const parsed = merovingian::homeserver::parse_federation_media_multipart(content_type, body);

            THEN("parsing fails closed because the spec requires exactly two parts")
            {
                REQUIRE_FALSE(parsed.ok);
            }
        }
    }
}

// SSRF-safe redirect following for the authenticated federation media endpoint.
// resolve_media_redirect_url() must only accept absolute https:// URLs and must
// pin only non-private/non-loopback addresses before the caller connects.
SCENARIO("resolve_media_redirect_url validates and resolves federation media redirect URLs safely",
         "[homeserver][media][federation][security]")
{
    GIVEN("a fake discovery network that returns controlled addresses")
    {
        auto network = FakeDiscoveryNetwork{};
        network.addresses["cdn.example.org"] = {"203.0.113.10"};
        network.addresses["v6.example.org"] = {"2001:db8::1"};
        network.addresses["2001:db8::1"] = {"2001:db8::1"};
        network.addresses["::1"] = {"::1"};
        network.addresses["private.example.org"] = {"192.168.1.1"};
        network.addresses["loopback.example.org"] = {"127.0.0.1"};

        WHEN("the redirect URL is a plain HTTPS URL with a public DNS name")
        {
            auto const result =
                merovingian::homeserver::resolve_media_redirect_url("https://cdn.example.org/media/abc123", network);

            THEN("resolution succeeds and pins the public address at the default port")
            {
                REQUIRE(result.ok);
                REQUIRE(result.discovery.discovery_allowed);
                REQUIRE(result.discovery.resolved_host == "cdn.example.org");
                REQUIRE(result.discovery.resolved_port == 443U);
                REQUIRE(result.discovery.pinned_addresses == std::vector<std::string>{"203.0.113.10"});
                REQUIRE(result.discovery.tls_required);
            }
        }

        WHEN("the redirect URL carries an explicit port")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://cdn.example.org:8443/media/abc123", network);

            THEN("the explicit port is preserved and the same address set is pinned")
            {
                REQUIRE(result.ok);
                REQUIRE(result.discovery.resolved_port == 8443U);
                REQUIRE(result.discovery.pinned_addresses == std::vector<std::string>{"203.0.113.10"});
            }
        }

        WHEN("the redirect URL uses an IPv6 literal")
        {
            auto const result =
                merovingian::homeserver::resolve_media_redirect_url("https://[2001:db8::1]:8443/media/abc123", network);

            THEN("resolution succeeds for the public IPv6 literal and pins it directly")
            {
                REQUIRE(result.ok);
                REQUIRE(result.discovery.resolved_host == "2001:db8::1");
                REQUIRE(result.discovery.resolved_port == 8443U);
                REQUIRE(result.discovery.pinned_addresses == std::vector<std::string>{"2001:db8::1"});
            }
        }

        WHEN("the redirect URL has a query string and fragment")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://cdn.example.org/media/abc123?token=secret#section", network);

            THEN("authority parsing ignores the query and fragment while preserving the path")
            {
                REQUIRE(result.ok);
                REQUIRE(result.discovery.resolved_host == "cdn.example.org");
            }
        }

        WHEN("the redirect URL uses cleartext http")
        {
            auto const result =
                merovingian::homeserver::resolve_media_redirect_url("http://cdn.example.org/media/abc123", network);

            THEN("resolution fails because federation media redirects must be HTTPS")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }

        WHEN("the redirect URL contains userinfo")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://user:pass@cdn.example.org/media/abc123", network);

            THEN("resolution fails because the authority is malformed")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }

        WHEN("the resolved host points to a private IP")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://private.example.org/media/abc123", network);

            THEN("resolution fails to prevent SSRF to internal infrastructure")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }

        WHEN("the resolved host points to loopback")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://loopback.example.org/media/abc123", network);

            THEN("resolution fails to prevent SSRF to the local host")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }

        WHEN("the host cannot be resolved")
        {
            auto const result = merovingian::homeserver::resolve_media_redirect_url(
                "https://missing.example.org/media/abc123", network);

            THEN("resolution fails because there are no pinned addresses")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }

        WHEN("the redirect URL uses an IPv6 loopback literal")
        {
            auto const result =
                merovingian::homeserver::resolve_media_redirect_url("https://[::1]/media/abc123", network);

            THEN("resolution fails because the literal is loopback")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.discovery.discovery_allowed);
            }
        }
    }
}
