// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0213: GET /_matrix/client/v1/media/preview_url makes this server fetch a
// URL a client names. These flows drive it against a real loopback HTTPS peer
// and a scripted resolver, and check the SSRF gate (literal and resolved
// private addresses, IPv6 included, and redirects into them), the byte and
// time caps, OpenGraph extraction, image storage through the media pipeline,
// and the cache.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::tests::tls_mock::MockIdentityServer;

constexpr auto preview_host = std::string_view{"preview.localhost.test"};

[[nodiscard]] auto preview_config(bool enabled) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.url_preview_enabled = enabled;
    security.media.url_preview_timeout_seconds = 2U;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// A resolver that answers from a fixed table and records what it was asked.
// Hosts it does not know resolve to nothing.
class ScriptedNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit ScriptedNetwork(std::map<std::string, std::vector<std::string>> answers, std::vector<std::string>& asked)
        : m_answers{std::move(answers)}
        , m_asked{asked}
    {
    }

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
        m_asked.emplace_back(host);
        auto const found = m_answers.find(std::string{host});
        if (found == m_answers.end())
        {
            return {false, {}, "no such host"};
        }
        return {true, found->second, {}};
    }

private:
    std::map<std::string, std::vector<std::string>> m_answers;
    // The fixture's record, which outlives the runtime that owns this network.
    std::vector<std::string>& m_asked;
};

[[nodiscard]] auto sample_png() -> std::string
{
    constexpr std::array<unsigned char, 81U> bytes{
        137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
        0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
        156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
        127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

[[nodiscard]] auto http_response(std::string_view status, std::string_view content_type, std::string const& body,
                                 std::string_view extra_headers = {}) -> std::string
{
    return "HTTP/1.1 " + std::string{status} + "\r\nContent-Type: " + std::string{content_type} +
           "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n" + std::string{extra_headers} +
           "Connection: close\r\n\r\n" + body;
}

[[nodiscard]] auto og_page() -> std::string
{
    return R"(<html><head><title>Fallback title</title>
<meta property="og:title" content="Matrix Blog Post">
<meta property="og:description" content="This is a really cool blog post from matrix.org">
<meta property="og:image" content="/logo.png">
<meta property="og:image:width" content="8">
<meta property="og:image:height" content="8">
</head><body>hello</body></html>)";
}

struct PreviewFixture final
{
    // Declared first so it is destroyed last: the runtime's network refers to it.
    std::vector<std::string> asked{};
    merovingian::homeserver::ClientServerStartResult started;
    std::string token{};

    explicit PreviewFixture(bool enabled = true)
        : started{merovingian::homeserver::start_client_server(preview_config(enabled))}
    {
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"PREVIEW"})"});
        REQUIRE(login.response.status == 200U);
        auto const body = parse_object(login.response.body);
        auto const* access_token = string_member(body, "access_token");
        REQUIRE(access_token != nullptr);
        token = *access_token;
        runtime.homeserver.discovery_network = std::make_unique<ScriptedNetwork>(
            std::map<std::string, std::vector<std::string>>{
                {"intranet.test",  {"10.1.2.3"}                },
                {"ula.test",       {"fd12:3456::1"}            },
                {"linklocal.test", {"fe80::1"}                 },
                {"mixed.test",     {"203.0.113.9", "127.0.0.1"}},
                {"metadata.test",  {"169.254.169.254"}         },
        },
            asked);
    }

    // Pins the mock server's host to loopback with its own certificate.
    auto pin(MockIdentityServer const& server) -> void
    {
        started.runtime.homeserver.test_forced_outbound_resolution[std::string{preview_host}] = {
            std::string{preview_host}, server.port(), {"127.0.0.1"}, server.certificate_pem()};
    }

    [[nodiscard]] auto preview(std::string const& url) -> merovingian::homeserver::DispatchResult
    {
        return merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"GET", "/_matrix/client/v1/media/preview_url?url=" + url + "&ts=1700000000000", token, {}});
    }
};

[[nodiscard]] auto mock_url(MockIdentityServer const& server, std::string_view path) -> std::string
{
    return "https://" + std::string{preview_host} + ":" + std::to_string(server.port()) + std::string{path};
}

} // namespace

SCENARIO("A URL preview returns the page's OpenGraph data with its image stored as media",
         "[integration][media][url-preview][preview]")
{
    GIVEN("URL previews enabled and a page with OpenGraph tags and a relative og:image")
    {
        auto fixture = PreviewFixture{};
        auto server = MockIdentityServer{
            {
             {"GET /page", http_response("200 OK", "text/html; charset=utf-8", og_page())},
             {"GET /logo.png", http_response("200 OK", "image/png", sample_png())},
             },
            std::string{preview_host                                                                            }
        };
        fixture.pin(server);

        WHEN("alice previews the page")
        {
            auto const response = fixture.preview(mock_url(server, "/page"));

            THEN("the OpenGraph properties are returned and og:image is an mxc:// URI with its size")
            {
                INFO(response.response.body);
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(string_member(body, "og:title") != nullptr);
                REQUIRE(*string_member(body, "og:title") == "Matrix Blog Post");
                REQUIRE(*string_member(body, "og:description") == "This is a really cool blog post from matrix.org");
                auto const* image = string_member(body, "og:image");
                REQUIRE(image != nullptr);
                REQUIRE(image->starts_with("mxc://example.org/"));
                auto const* size = int_member(body, "matrix:image:size");
                REQUIRE(size != nullptr);
                REQUIRE(*size == static_cast<std::int64_t>(sample_png().size()));
                REQUIRE(*int_member(body, "og:image:width") == 8);

                AND_THEN("the image is served from this server's media repository")
                {
                    auto const media_id = image->substr(std::string_view{"mxc://example.org/"}.size());
                    auto const downloaded = merovingian::homeserver::handle_client_server_request(
                        fixture.started.runtime,
                        {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, fixture.token, {}});
                    REQUIRE(downloaded.response.status == 200U);
                    REQUIRE(downloaded.response.body == sample_png());
                }
            }

            AND_WHEN("the same URL is previewed again")
            {
                auto const again = fixture.preview(mock_url(server, "/page"));

                THEN("the cached preview is returned without fetching the page again")
                {
                    REQUIRE(again.response.status == 200U);
                    REQUIRE(again.response.body == response.response.body);
                    REQUIRE(server.count_requests("GET /page") == 1U);
                }
            }
        }

        WHEN("the deprecated v3 route previews it")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                fixture.started.runtime,
                {"GET", "/_matrix/media/v3/preview_url?url=" + mock_url(server, "/page"), fixture.token, {}});

            THEN("it answers the same way")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("Matrix Blog Post") != std::string::npos);
            }
        }
    }

    GIVEN("a URL whose content is not HTML")
    {
        auto fixture = PreviewFixture{};
        auto server = MockIdentityServer{
            {
             {"GET /data.json", http_response("200 OK", "application/json", R"({"a":1})")},
             },
            std::string{preview_host}
        };
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const response = fixture.preview(mock_url(server, "/data.json"));

            THEN("the preview is an empty object")
            {
                // Spec: "The OpenGraph data for the URL, which may be empty."
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

SCENARIO("URL previews refuse private, loopback, link-local and metadata destinations",
         "[integration][media][url-preview][preview][security][ssrf]")
{
    GIVEN("URL previews enabled")
    {
        auto fixture = PreviewFixture{};

        WHEN("literal addresses in protected ranges are previewed")
        {
            auto const targets = std::vector<std::string>{
                "https://127.0.0.1/", "http://127.0.0.1:8008/_matrix/client/versions",
                "http://10.0.0.1/",   "http://192.168.1.1/",
                "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data/",
                "https://[::1]/",     "https://[fe80::1]/",
                "https://[fd00::1]/", "https://[::ffff:127.0.0.1]/",
                "http://100.64.0.1/", "http://0.0.0.0/",
            };
            auto statuses = std::vector<std::uint16_t>{};
            for (auto const& target : targets)
            {
                statuses.push_back(fixture.preview(target).response.status);
            }

            THEN("every one is refused with the same 502 and nothing is resolved")
            {
                for (auto const status : statuses)
                {
                    REQUIRE(status == 502U);
                }
                REQUIRE(fixture.asked.empty());
            }
        }

        WHEN("names that resolve into protected ranges are previewed")
        {
            auto const ipv4 = fixture.preview("https://intranet.test/secret");
            auto const ula = fixture.preview("https://ula.test/");
            auto const link_local = fixture.preview("https://linklocal.test/");
            auto const mixed = fixture.preview("https://mixed.test/");
            auto const metadata = fixture.preview("http://metadata.test/latest/meta-data/");

            THEN("each is refused after resolution: one private address is enough")
            {
                REQUIRE(ipv4.response.status == 502U);
                REQUIRE(ula.response.status == 502U);
                REQUIRE(link_local.response.status == 502U);
                REQUIRE(mixed.response.status == 502U);
                REQUIRE(metadata.response.status == 502U);
                REQUIRE(fixture.asked.size() == 5U);
            }

            THEN("the refusal does not say why, so it is no oracle for internal names")
            {
                REQUIRE(ipv4.response.body == ula.response.body);
                auto const unknown = fixture.preview("https://nonexistent.test/");
                REQUIRE(unknown.response.status == 502U);
                REQUIRE(unknown.response.body == ipv4.response.body);
            }
        }

        WHEN("a URL with another scheme, credentials or no host is previewed")
        {
            auto const file = fixture.preview("file:///etc/passwd");
            auto const gopher = fixture.preview("gopher://example.com/");
            auto const userinfo = fixture.preview("https://user:pass@example.com/");
            auto const missing = merovingian::homeserver::handle_client_server_request(
                fixture.started.runtime, {"GET", "/_matrix/client/v1/media/preview_url", fixture.token, {}});

            THEN("each is refused as a bad parameter before anything is resolved")
            {
                REQUIRE(file.response.status == 400U);
                REQUIRE(gopher.response.status == 400U);
                REQUIRE(userinfo.response.status == 400U);
                REQUIRE(missing.response.status == 400U);
                REQUIRE(parse_object(missing.response.body).size() >= 1U);
                REQUIRE(fixture.asked.empty());
            }
        }
    }

    GIVEN("a public page that redirects into a private address")
    {
        auto fixture = PreviewFixture{};
        auto server = MockIdentityServer{
            {
             {"GET /hop", http_response("302 Found", "text/html", "", "Location: https://intranet.test/secret\r\n")},
             },
            std::string{preview_host}
        };
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const response = fixture.preview(mock_url(server, "/hop"));

            THEN("the redirect target is checked like the first hop and refused")
            {
                REQUIRE(response.response.status == 502U);
                REQUIRE(server.count_requests("GET /hop") == 1U);
                REQUIRE(fixture.asked.size() == 1U);
                REQUIRE(fixture.asked.front() == "intranet.test");
            }
        }
    }

    GIVEN("a public page whose og:image points into a private address")
    {
        auto fixture = PreviewFixture{};
        auto const page = std::string{R"(<html><head>
<meta property="og:title" content="Image elsewhere">
<meta property="og:image" content="http://metadata.test/latest/meta-data/x.png">
</head></html>)"};
        auto server = MockIdentityServer{
            {
             {"GET /page", http_response("200 OK", "text/html", page)},
             },
            std::string{preview_host}
        };
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const response = fixture.preview(mock_url(server, "/page"));

            THEN("the image hop is checked like the page and refused, and the preview leaves the image out")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(string_member(body, "og:title") != nullptr);
                REQUIRE(string_member(body, "og:image") == nullptr);
                REQUIRE(fixture.asked.size() == 1U);
                REQUIRE(fixture.asked.front() == "metadata.test");
            }
        }
    }

    GIVEN("a page that redirects more times than the cap allows")
    {
        auto fixture = PreviewFixture{};
        fixture.started.runtime.homeserver.media_repository.config.url_preview_max_redirects = 1U;
        auto server = MockIdentityServer{
            {
             {"GET /one", http_response("302 Found", "text/html", "", "Location: /two\r\n")},
             {"GET /two", http_response("302 Found", "text/html", "", "Location: /three\r\n")},
             {"GET /three", http_response("200 OK", "text/html", og_page())},
             },
            std::string{preview_host}
        };
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const response = fixture.preview(mock_url(server, "/one"));

            THEN("the chain is abandoned at the cap")
            {
                REQUIRE(response.response.status == 502U);
                REQUIRE(server.count_requests("GET /three") == 0U);
            }
        }
    }
}

SCENARIO("URL preview fetches are capped in bytes and time", "[integration][media][url-preview][preview][security]")
{
    GIVEN("a page larger than url_preview_max_page_size")
    {
        auto fixture = PreviewFixture{};
        fixture.started.runtime.homeserver.media_repository.config.url_preview_max_page_bytes = 1024U;
        auto const large = "<html><head><title>big</title></head><body>" + std::string(8192U, 'x') + "</body></html>";
        auto server = MockIdentityServer{
            {
             {"GET /big", http_response("200 OK", "text/html", large)},
             {"GET /small", http_response("200 OK", "text/html", og_page().substr(0U, 200U))},
             },
            std::string{preview_host                                                        }
        };
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const big = fixture.preview(mock_url(server, "/big"));
            auto const small = fixture.preview(mock_url(server, "/small"));

            THEN("the oversized page is refused and a page within the cap is previewed")
            {
                REQUIRE(big.response.status == 502U);
                REQUIRE(small.response.status == 200U);
            }
        }
    }

    GIVEN("a server that accepts the request and then stalls")
    {
        auto fixture = PreviewFixture{};
        fixture.started.runtime.homeserver.media_repository.config.url_preview_timeout_seconds = 1U;
        auto server = MockIdentityServer{
            {
             {"GET /slow", http_response("200 OK", "text/html", og_page())},
             },
            std::string{preview_host}
        };
        server.stall_requests_matching("GET /slow");
        fixture.pin(server);

        WHEN("it is previewed")
        {
            auto const started_at = std::chrono::steady_clock::now();
            auto const response = fixture.preview(mock_url(server, "/slow"));
            auto const waited = std::chrono::steady_clock::now() - started_at;
            server.release_stall();

            THEN("the preview gives up at its deadline")
            {
                REQUIRE(response.response.status == 502U);
                REQUIRE(waited < std::chrono::seconds{5});
            }
        }
    }
}

// Spec: GET /_matrix/client/v1/media/preview_url "Requires authentication: Yes".
SCENARIO("URL previews are off unless enabled, and always require authentication",
         "[integration][media][url-preview][preview]")
{
    GIVEN("a server with the default configuration")
    {
        auto fixture = PreviewFixture{false};

        WHEN("a client asks for a preview")
        {
            auto const response = fixture.preview("https://example.com/");

            THEN("the endpoint answers 404 M_UNRECOGNIZED and nothing is resolved")
            {
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_UNRECOGNIZED");
                REQUIRE(fixture.asked.empty());
            }
        }

        WHEN("a client without an access token asks")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                fixture.started.runtime,
                {"GET", "/_matrix/client/v1/media/preview_url?url=https://example.com/", {}, {}});

            THEN("the request is refused as unauthenticated")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}
