// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth::ParsedUri, oauth::ClientUri and the redirect URI rules (spec v1.19 Client-Server API "Redirect URI
// validation", RFC 8252 section 7; ADR-0770, ADR-0771).

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientUri.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/RedirectUriRules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::oauth::ApplicationType;
using merovingian::oauth::ClientUri;
using merovingian::oauth::OAuthRefusal;
using merovingian::oauth::ParsedUri;

[[nodiscard]] auto client(std::string_view text) -> ClientUri
{
    auto read = ClientUri::read(text);
    REQUIRE(std::holds_alternative<ClientUri>(read));
    return std::get<ClientUri>(std::move(read));
}

[[nodiscard]] auto accepted(std::string_view uri, ApplicationType type, ClientUri const& base) -> bool
{
    return std::holds_alternative<ParsedUri>(merovingian::oauth::validate_redirect_uri(uri, type, base));
}

[[nodiscard]] auto refused_as_redirect(std::string_view uri, ApplicationType type, ClientUri const& base) -> bool
{
    auto const result = merovingian::oauth::validate_redirect_uri(uri, type, base);
    auto const* refusal = std::get_if<OAuthRefusal>(&result);
    return refusal != nullptr && refusal->error_code == merovingian::oauth::error_invalid_redirect_uri;
}

[[nodiscard]] auto reads(std::string_view text) -> bool
{
    return std::holds_alternative<ParsedUri>(ParsedUri::read(text));
}

[[nodiscard]] auto matches(std::string_view requested, ApplicationType type, std::vector<std::string> const& registered)
    -> bool
{
    return merovingian::oauth::match_redirect_uri(requested, type, registered).has_value();
}

} // namespace

SCENARIO("The URI reader splits an absolute URI into its parts", "[oauth][uri]")
{
    GIVEN("an https URI with a port, path and query, and a private-use URI with no authority")
    {
        WHEN("each is read")
        {
            auto web = ParsedUri::read("https://App.Example.com:5173/cb/x?query=value&b=%2F");
            auto native = ParsedUri::read("com.example.app:/callback");

            THEN("every field is the bytes given, and the CSP source is built from scheme, host and port")
            {
                REQUIRE(std::holds_alternative<ParsedUri>(web));
                auto const& w = std::get<ParsedUri>(web);
                REQUIRE(w.scheme() == "https");
                REQUIRE(w.has_authority());
                REQUIRE(w.host() == "App.Example.com");
                REQUIRE(w.port() == std::uint16_t{5173U});
                REQUIRE(w.path() == "/cb/x");
                REQUIRE(w.has_query());
                REQUIRE(w.query() == "query=value&b=%2F");
                REQUIRE(w.csp_source() == "https://App.Example.com:5173");

                REQUIRE(std::holds_alternative<ParsedUri>(native));
                auto const& n = std::get<ParsedUri>(native);
                REQUIRE_FALSE(n.has_authority());
                REQUIRE(n.host().empty());
                REQUIRE(n.path() == "/callback");
                REQUIRE(n.csp_source() == "com.example.app:");
            }
        }
    }
}

SCENARIO("The URI reader refuses hostile and ambiguous forms", "[oauth][uri][security]")
{
    GIVEN("URIs with a fragment, userinfo, escapes in the host, control bytes, backslashes and bad ports")
    {
        auto const refused = std::array<std::string_view, 30>{
            "https://example.com/cb#fragment",
            "https://example.com/cb#",
            "https://user@example.com/",
            "https://user:pass@example.com/",
            "https://@example.com/",
            "https://exa%6Dple.com/",
            "https://example.com./",
            "https://.example.com/",
            "https://exa..mple.com/",
            "https://-example.com/",
            "https://example-.com/",
            "https://exa_mple.com/",
            "https://example.com\\@evil.example/",
            "https://example.com/\\evil",
            "https://example.com/a b",
            "https://example.com/\t",
            "https://example.com:0/",
            "https://example.com:65536/",
            "https://example.com:0443/",
            "https://example.com:/",
            "https://example.com:12a/",
            "https:///path",
            "https://[::1/",
            "https://[example.com]/",
            "https://example.com/%zz",
            "https://example.com/%4",
            "https://example.com/<script>",
            "https://example.com/\"",
            "://example.com/",
            "1https://example.com/",
        };

        WHEN("each is read")
        {
            THEN("each is refused")
            {
                for (auto const text : refused)
                {
                    INFO(text);
                    REQUIRE_FALSE(reads(text));
                }
            }
        }
    }
}

SCENARIO("The URI reader refuses NUL, non-ASCII and over-long input", "[oauth][uri][boundary]")
{
    GIVEN("a URI with an embedded NUL, one with a UTF-8 host, one of 2048 bytes and one of 2049")
    {
        auto with_nul = std::string{"https://example.com/a"};
        with_nul.push_back('\0');
        with_nul.append("b");
        auto const utf8_host = std::string{"https://ex\xc3\xa4mple.com/"};
        auto const prefix = std::string{"https://example.com/"};
        auto const at_cap = prefix + std::string(ParsedUri::max_uri_bytes - prefix.size(), 'a');
        auto const over_cap = at_cap + "a";

        WHEN("each is read")
        {
            auto const over = ParsedUri::read(over_cap);

            THEN("only the 2048-byte URI is read, and the over-long one fails as a cap")
            {
                REQUIRE_FALSE(reads(with_nul));
                REQUIRE_FALSE(reads(utf8_host));
                REQUIRE(reads(at_cap));
                REQUIRE(std::holds_alternative<merovingian::core::Error>(over));
                REQUIRE(std::get<merovingian::core::Error>(over).code() ==
                        merovingian::core::ErrorCode::invalid_argument);
                REQUIRE_FALSE(reads(""));
            }
        }
    }
}

SCENARIO("The spec's web redirect URI examples are classified as the spec says", "[oauth][redirect]")
{
    // Spec v1.19 Client-Server API, "Redirect URI validation", web clients, with https://example.com/ as client URI.
    GIVEN("the client URI https://example.com/ and a web client")
    {
        auto const base = client("https://example.com/");

        WHEN("the spec's three valid and three invalid examples are validated")
        {
            THEN("the valid ones are accepted and the invalid ones refused with invalid_redirect_uri")
            {
                REQUIRE(accepted("https://example.com/callback", ApplicationType::web, base));
                REQUIRE(accepted("https://app.example.com/callback", ApplicationType::web, base));
                REQUIRE(accepted("https://example.com:5173/?query=value", ApplicationType::web, base));

                REQUIRE(refused_as_redirect("https://example.com/callback#fragment", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("http://example.com/callback", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("http://localhost/", ApplicationType::web, base));
            }
        }
    }
}

SCENARIO("The spec's native redirect URI examples are classified as the spec says", "[oauth][redirect]")
{
    // Spec v1.19 Client-Server API, "Redirect URI validation", native clients, with https://example.com/ as client URI.
    GIVEN("the client URI https://example.com/ and a native client")
    {
        auto const base = client("https://example.com/");

        WHEN("the spec's six valid and four invalid examples are validated")
        {
            THEN("the valid ones are accepted and the invalid ones refused with invalid_redirect_uri")
            {
                REQUIRE(accepted("com.example.app:/callback", ApplicationType::native, base));
                REQUIRE(accepted("com.example:/", ApplicationType::native, base));
                REQUIRE(accepted("com.example:callback", ApplicationType::native, base));
                REQUIRE(accepted("http://localhost/callback", ApplicationType::native, base));
                REQUIRE(accepted("http://127.0.0.1/callback", ApplicationType::native, base));
                REQUIRE(accepted("http://[::1]/callback", ApplicationType::native, base));

                REQUIRE(refused_as_redirect("example:/callback", ApplicationType::native, base));
                REQUIRE(refused_as_redirect("com.example.app://callback", ApplicationType::native, base));
                REQUIRE(refused_as_redirect("https://localhost/callback", ApplicationType::native, base));
                REQUIRE(refused_as_redirect("http://localhost:1234/callback", ApplicationType::native, base));
            }
        }
    }
}

SCENARIO("A native client may also register a claimed https URI on its host", "[oauth][redirect]")
{
    GIVEN("the client URI https://example.com/ and a native client")
    {
        auto const base = client("https://example.com/");

        WHEN("claimed https URIs on and off the host are validated")
        {
            THEN("the ones on the host or a subdomain are accepted")
            {
                REQUIRE(accepted("https://example.com/oauth", ApplicationType::native, base));
                REQUIRE(accepted("https://ios.example.com/oauth", ApplicationType::native, base));
                REQUIRE(refused_as_redirect("https://example.org/oauth", ApplicationType::native, base));
            }
        }
    }
}

SCENARIO("The web host rule respects label boundaries and case", "[oauth][redirect][security]")
{
    GIVEN("the client URI https://Example.COM/")
    {
        auto const base = client("https://Example.COM/");

        WHEN("hosts that share a suffix without a label boundary, or differ only in case, are validated")
        {
            THEN("only equal hosts and real subdomains pass")
            {
                REQUIRE(accepted("https://EXAMPLE.com/cb", ApplicationType::web, base));
                REQUIRE(accepted("https://a.b.example.com/cb", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("https://notexample.com/cb", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("https://example.com.evil.example/cb", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("https://evil.example/example.com", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("HTTPS://example.com/cb", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("https://user@example.com/cb", ApplicationType::web, base));
            }
        }
    }
}

SCENARIO("Loopback and private-use redirect URIs refuse look-alikes", "[oauth][redirect][security]")
{
    GIVEN("the client URI https://example.com/ and a native client")
    {
        auto const base = client("https://example.com/");

        WHEN("hostile loopback and scheme forms are validated")
        {
            THEN("each is refused")
            {
                for (auto const uri : std::array<std::string_view, 15>{
                         "http://localhost.evil.example/",
                         "http://127.0.0.1.evil.example/",
                         "http://LOCALHOST/cb",
                         "http://127.1/cb",
                         "http://0x7f.0.0.1/cb",
                         "http://[0:0:0:0:0:0:0:1]/cb",
                         "http://[::ffff:127.0.0.1]/cb",
                         "http://user@localhost/cb",
                         "http://localhost:0/cb",
                         "http://localhost./cb",
                         "com.exampleevil:/",
                         "com.example.:/",
                         "com.examplex.app:/cb",
                         "org.example:/cb",
                         "com.example:/cb#x",
                     })
                {
                    INFO(uri);
                    REQUIRE_FALSE(accepted(uri, ApplicationType::native, base));
                }
            }
        }
        AND_WHEN("the scheme differs only in case")
        {
            THEN("it is compared case-insensitively")
            {
                REQUIRE(accepted("COM.Example.App:/cb", ApplicationType::native, base));
            }
        }
    }
}

SCENARIO("A web client cannot register native-only redirect URIs", "[oauth][redirect]")
{
    GIVEN("the client URI https://example.com/ and a web client")
    {
        auto const base = client("https://example.com/");

        WHEN("a private-use and a loopback URI are validated")
        {
            THEN("both are refused")
            {
                REQUIRE(refused_as_redirect("com.example.app:/callback", ApplicationType::web, base));
                REQUIRE(refused_as_redirect("http://127.0.0.1/callback", ApplicationType::web, base));
            }
        }
    }
}

SCENARIO("A client URI must be https on a DNS name of two or more labels", "[oauth][redirect][security]")
{
    GIVEN("client URIs on IP literals, loopback names, single labels, http, or with userinfo or a fragment")
    {
        auto const refused = std::array<std::string_view, 11>{
            "http://example.com/",  "https://localhost/", "https://app.localhost/",    "https://127.0.0.1/",
            "https://[::1]/",       "https://example/",   "https://user@example.com/", "https://example.com/#",
            "https://example.123/", "com.example:/",      "https:example.com",
        };

        WHEN("each is read")
        {
            THEN("each is refused with invalid_client_metadata")
            {
                for (auto const text : refused)
                {
                    INFO(text);
                    auto const result = ClientUri::read(text);
                    auto const* refusal = std::get_if<OAuthRefusal>(&result);
                    REQUIRE(refusal != nullptr);
                    REQUIRE(refusal->error_code == merovingian::oauth::error_invalid_client_metadata);
                }
            }
        }
        AND_WHEN("a valid one with a port, path and query is read")
        {
            auto const base = client("https://App.Example.com:8443/about?x=1");

            THEN("its host is lowered and reversed")
            {
                REQUIRE(base.host_lower() == "app.example.com");
                REQUIRE(base.reversed_host_lower() == "com.example.app");
            }
        }
    }
}

SCENARIO("An authorisation request's redirect_uri must match a registered one exactly", "[oauth][redirect]")
{
    GIVEN("a web client that registered one URI with a query")
    {
        auto const registered = std::vector<std::string>{"https://app.example.com/cb?x=1"};

        WHEN("the same bytes and near misses are matched")
        {
            THEN("only the same bytes match")
            {
                REQUIRE(matches("https://app.example.com/cb?x=1", ApplicationType::web, registered));
                REQUIRE_FALSE(matches("https://app.example.com/cb?x=2", ApplicationType::web, registered));
                REQUIRE_FALSE(matches("https://APP.example.com/cb?x=1", ApplicationType::web, registered));
                REQUIRE_FALSE(matches("https://app.example.com:443/cb?x=1", ApplicationType::web, registered));
                REQUIRE_FALSE(matches("https://app.example.com/cb?x=1#", ApplicationType::web, registered));
                REQUIRE_FALSE(matches("https://app.example.com/cb", ApplicationType::web, registered));
            }
        }
    }
}

SCENARIO("A native loopback URI registered without a port matches any port", "[oauth][redirect][boundary]")
{
    GIVEN("a native client that registered http://127.0.0.1/callback and http://[::1]/cb")
    {
        auto const registered = std::vector<std::string>{"http://127.0.0.1/callback", "http://[::1]/cb"};

        WHEN("requests with ports and with altered paths are matched")
        {
            using merovingian::oauth::match_redirect_uri;
            auto const with_port =
                match_redirect_uri("http://127.0.0.1:51234/callback", ApplicationType::native, registered);

            THEN("ports 1 to 65535 match, everything else does not")
            {
                REQUIRE(with_port.has_value());
                REQUIRE(with_port->port() == std::uint16_t{51234U});
                REQUIRE(matches("http://127.0.0.1/callback", ApplicationType::native, registered));
                REQUIRE(matches("http://127.0.0.1:1/callback", ApplicationType::native, registered));
                REQUIRE(matches("http://127.0.0.1:65535/callback", ApplicationType::native, registered));
                REQUIRE(matches("http://[::1]:8080/cb", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://127.0.0.1:0/callback", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://127.0.0.1:65536/callback", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://127.0.0.1:080/callback", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://127.0.0.1:8080/callback2", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://localhost:8080/callback", ApplicationType::native, registered));
                REQUIRE_FALSE(matches("http://[::1]:8080/callback", ApplicationType::native, registered));
            }
        }
        AND_WHEN("a web client presents the same loopback URI with a port")
        {
            THEN("the port rule does not apply")
            {
                REQUIRE_FALSE(matches("http://127.0.0.1:8080/callback", ApplicationType::web, registered));
            }
        }
    }
}
