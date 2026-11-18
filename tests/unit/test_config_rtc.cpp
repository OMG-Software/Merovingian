// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.rtc.livekit.service_url: where MatrixRTC clients get a LiveKit token (MSC4143, MSC4195; ADR-0822). The
// routes that advertise it are not in Matrix v1.19, so these are project-level checks.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/ServerConfig.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto has_finding(std::vector<merovingian::config::ConfigValidationFinding> const& findings,
                               std::string_view field) -> bool
{
    for (auto const& finding : findings)
    {
        if (finding.field == field)
        {
            return true;
        }
    }
    return false;
}

[[nodiscard]] auto parse_url(std::string const& url) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config("server.rtc.livekit.service_url=" + url + "\n");
}

} // namespace

SCENARIO("server.rtc.livekit.service_url accepts an https URL and defaults to none", "[config][rtc]")
{
    GIVEN("a configuration that does not mention the key")
    {
        WHEN("it is parsed")
        {
            auto const parsed = merovingian::config::parse_key_value_config("");

            THEN("no transport is configured and nothing is reported")
            {
                CHECK(parsed.config.server().rtc.livekit_service_url.empty());
                CHECK_FALSE(has_finding(parsed.findings, "server.rtc.livekit.service_url"));
            }
        }
    }

    GIVEN("a valid https URL, with a port and a path")
    {
        WHEN("it is parsed")
        {
            auto const parsed = parse_url("https://livekit-jwt.example.org:8443/lk-jwt-service");

            THEN("it is kept exactly as written")
            {
                CHECK_FALSE(has_finding(parsed.findings, "server.rtc.livekit.service_url"));
                CHECK(parsed.config.server().rtc.livekit_service_url ==
                      "https://livekit-jwt.example.org:8443/lk-jwt-service");
            }
        }
    }
}

SCENARIO("server.rtc.livekit.service_url accepts a URL a client can append to", "[config][rtc]")
{
    GIVEN("URLs that /sfu/get or /get_token can be appended to")
    {
        auto const good_urls = std::vector<std::string>{"https://livekit-jwt.example.org",
                                                        "https://livekit-jwt.example.org:8443", "https://[2001:db8::1]",
                                                        "https://[2001:db8::1]:8443/jwt", "https://example.org/a/b"};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const& good : good_urls)
            {
                parsed.push_back(parse_url(good));
            }

            THEN("each is accepted: a bare host, a port, an IPv6 literal, a path with no trailing slash")
            {
                REQUIRE(parsed.size() == good_urls.size());
                for (auto index = std::size_t{0U}; index < good_urls.size(); ++index)
                {
                    INFO(good_urls[index]);
                    REQUIRE_FALSE(has_finding(parsed[index].findings, "server.rtc.livekit.service_url"));
                    REQUIRE(parsed[index].config.server().rtc.livekit_service_url == good_urls[index]);
                }
            }
        }
    }
}

SCENARIO("server.rtc.livekit.service_url refuses anything but a plain https URL", "[config][rtc]")
{
    GIVEN("values that are not acceptable")
    {
        auto const long_url = "https://example.org/" + std::string(2100U, 'a');
        auto const bad = std::vector<std::string>{
            "http://livekit.example.org",
            "HTTPS://livekit.example.org",
            "ftp://livekit.example.org",
            "livekit.example.org",
            "//livekit.example.org",
            "https://",
            "https:///path",
            "https://user@livekit.example.org",
            "https://user:pw@livekit.example.org",
            "https://livekit.example.org/#frag",
            "https://livekit.example.org/a b",
            "https://livekit.example.org/\x01",
            "https://livekit.example.org/caf\xC3\xA9",
            "https://livekit.example.org/x?a=1",
            "https://livekit.example.org?a=1",
            "https://livekit.example.org/x?",
            "https://livekit.example.org/jwt/",
            "https://livekit.example.org/",
            "https://livekit.example.org:8443/",
            long_url,
        };

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const& url : bad)
            {
                parsed.push_back(parse_url(url));
            }

            THEN("each is refused with a finding on the key, and is never repaired")
            {
                REQUIRE(parsed.size() == bad.size());
                for (auto index = std::size_t{0U}; index < bad.size(); ++index)
                {
                    INFO(bad[index].substr(0U, 60U));
                    REQUIRE(has_finding(parsed[index].findings, "server.rtc.livekit.service_url"));
                    REQUIRE_FALSE(merovingian::config::is_valid(parsed[index].config));
                }
            }
        }
    }
}

SCENARIO("server.rtc.livekit.service_url is reloadable and diffed by the reload plan", "[config][rtc]")
{
    GIVEN("two configurations that differ only in the service URL")
    {
        auto const before = parse_url("https://a.example.org");
        auto const after = parse_url("https://b.example.org");

        WHEN("a reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);

            THEN("the key is named and needs no restart")
            {
                auto found = false;
                for (auto const& change : plan.changes())
                {
                    found = found || change.key == "server.rtc.livekit.service_url";
                }
                CHECK(found);
                CHECK(merovingian::config::reload_policy_for_key("server.rtc.livekit.service_url") ==
                      merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}

namespace
{

constexpr auto token_service_keys = std::string_view{"server.rtc.livekit.url=wss://sfu.example.org\n"
                                                     "server.rtc.livekit.api_url=https://sfu.example.org\n"
                                                     "server.rtc.livekit.api_key=APIkey_1\n"
                                                     "server.rtc.livekit.api_secret_file=/etc/merovingian/livekit\n"};

[[nodiscard]] auto parse_token_service(std::string const& extra) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config(std::string{token_service_keys} + extra);
}

[[nodiscard]] auto with_value(std::string_view key, std::string const& value) -> merovingian::config::ConfigParseResult
{
    auto text = std::string{token_service_keys};
    auto const start = text.find(std::string{key} + "=");
    REQUIRE(start != std::string::npos);
    auto const end = text.find('\n', start);
    text.replace(start, end - start, std::string{key} + "=" + value);
    return merovingian::config::parse_key_value_config(text);
}

[[nodiscard]] auto plan_names(merovingian::config::ReloadPlan const& plan, std::string const& key) -> bool
{
    for (auto const& change : plan.changes())
    {
        if (change.key == key)
        {
            return true;
        }
    }
    return false;
}

} // namespace

SCENARIO("The built-in LiveKit token service is configured by four keys together", "[config][rtc][livekit]")
{
    GIVEN("the four keys with valid values and no lifetime")
    {
        WHEN("they are parsed and validated")
        {
            auto const parsed = parse_token_service("");
            auto const findings = merovingian::config::validate(parsed.config);
            auto const& service = parsed.config.server().rtc.token_service;

            THEN("they are kept as written, the lifetime is one hour, and nothing is reported")
            {
                CHECK(parsed.findings.empty());
                CHECK(findings.empty());
                CHECK(service.url == "wss://sfu.example.org");
                CHECK(service.api_url == "https://sfu.example.org");
                CHECK(service.api_key == "APIkey_1");
                CHECK(service.api_secret_file == "/etc/merovingian/livekit");
                CHECK(service.token_lifetime_seconds == 3600U);
            }
        }
    }

    GIVEN("a configuration that does not mention them")
    {
        WHEN("it is validated")
        {
            auto const parsed = merovingian::config::parse_key_value_config("");

            THEN("the service is off and nothing is reported")
            {
                CHECK(parsed.config.server().rtc.token_service.url.empty());
                CHECK(merovingian::config::is_valid(parsed.config));
            }
        }
    }

    GIVEN("each key alone")
    {
        auto const keys = std::vector<std::string>{
            "server.rtc.livekit.url=wss://sfu.example.org", "server.rtc.livekit.api_url=https://sfu.example.org",
            "server.rtc.livekit.api_key=APIkey_1", "server.rtc.livekit.api_secret_file=/etc/merovingian/livekit"};

        WHEN("each is validated without the other three")
        {
            THEN("each is refused, with a finding on every missing key")
            {
                for (auto const& line : keys)
                {
                    INFO(line);
                    auto const parsed = merovingian::config::parse_key_value_config(line + "\n");
                    auto const findings = merovingian::config::validate(parsed.config);
                    CHECK_FALSE(merovingian::config::is_valid(parsed.config));
                    auto missing = std::size_t{0U};
                    for (auto const& finding : findings)
                    {
                        missing += finding.message.find("together") != std::string::npos ? 1U : 0U;
                    }
                    CHECK(missing == 3U);
                }
            }
        }
    }

    GIVEN("the four keys and the external service URL")
    {
        WHEN("they are validated")
        {
            auto const parsed = parse_token_service("server.rtc.livekit.service_url=https://jwt.example.org\n");
            auto const findings = merovingian::config::validate(parsed.config);

            THEN("the combination is refused on the service URL")
            {
                CHECK(has_finding(findings, "server.rtc.livekit.service_url"));
                CHECK_FALSE(merovingian::config::is_valid(parsed.config));
            }
        }
    }
}

SCENARIO("The built-in token service refuses a value it cannot use, and never repairs it",
         "[config][rtc][livekit][negative]")
{
    GIVEN("acceptable and unacceptable values for each key")
    {
        struct Case
        {
            std::string_view key;
            std::string value;
            bool accepted;
        };
        auto const cases = std::vector<Case>{
            {"server.rtc.livekit.url", "wss://sfu.example.org:7880", true},
            {"server.rtc.livekit.url", "wss://sfu.example.org/livekit", true},
            {"server.rtc.livekit.url", "ws://sfu.example.org", false},
            {"server.rtc.livekit.url", "https://sfu.example.org", false},
            {"server.rtc.livekit.url", "wss://sfu.example.org/", false},
            {"server.rtc.livekit.url", "wss://sfu.example.org?a=1", false},
            {"server.rtc.livekit.url", "wss://user@sfu.example.org", false},
            {"server.rtc.livekit.url", "wss://sfu.example.org/#x", false},
            {"server.rtc.livekit.url", "wss://", false},
            {"server.rtc.livekit.url", "wss://sfu.example.org/" + std::string(2100U, 'a'), false},
            {"server.rtc.livekit.api_url", "https://sfu.example.org:7880", true},
            {"server.rtc.livekit.api_url", "http://127.0.0.1:7880", true},
            {"server.rtc.livekit.api_url", "http://[::1]:7880", true},
            {"server.rtc.livekit.api_url", "http://sfu.example.org:7880", false},
            {"server.rtc.livekit.api_url", "http://10.0.0.5:7880", false},
            {"server.rtc.livekit.api_url", "http://localhost:7880", false},
            {"server.rtc.livekit.api_url", "wss://sfu.example.org", false},
            {"server.rtc.livekit.api_url", "https://sfu.example.org/", false},
            {"server.rtc.livekit.api_url", "https://sfu.example.org/?x", false},
            {"server.rtc.livekit.api_key", "API.key-1_x", true},
            {"server.rtc.livekit.api_key", std::string(128U, 'k'), true},
            {"server.rtc.livekit.api_key", std::string(129U, 'k'), false},
            {"server.rtc.livekit.api_key", "key with space", false},
            {"server.rtc.livekit.api_key", "key\"quote", false},
            {"server.rtc.livekit.api_key", "k\xC3\xA9y", false},
        };

        WHEN("each is put in an otherwise valid configuration")
        {
            THEN("only the acceptable ones pass, and a refusal names the key")
            {
                for (auto const& entry : cases)
                {
                    INFO(std::string{entry.key} + "=" + entry.value.substr(0U, 60U));
                    auto const parsed = with_value(entry.key, entry.value);
                    auto const findings = merovingian::config::validate(parsed.config);
                    CHECK((has_finding(findings, entry.key) || has_finding(parsed.findings, entry.key)) ==
                          !entry.accepted);
                    CHECK(merovingian::config::is_valid(parsed.config) == entry.accepted);
                }
            }
        }
    }

    GIVEN("token lifetimes at and beyond the bounds")
    {
        WHEN("each is parsed and validated")
        {
            auto const at_low = parse_token_service("server.rtc.livekit.token_lifetime=60s\n");
            auto const at_high = parse_token_service("server.rtc.livekit.token_lifetime=60m\n");
            auto const below = parse_token_service("server.rtc.livekit.token_lifetime=59s\n");
            auto const above = parse_token_service("server.rtc.livekit.token_lifetime=3601s\n");
            auto const zero = parse_token_service("server.rtc.livekit.token_lifetime=0s\n");
            auto const garbage = parse_token_service("server.rtc.livekit.token_lifetime=1h\n");

            THEN("60s and 60m pass and everything else is refused")
            {
                CHECK(merovingian::config::is_valid(at_low.config));
                CHECK(at_low.config.server().rtc.token_service.token_lifetime_seconds == 60U);
                CHECK(merovingian::config::is_valid(at_high.config));
                CHECK(at_high.config.server().rtc.token_service.token_lifetime_seconds == 3600U);
                CHECK(has_finding(merovingian::config::validate(below.config), "server.rtc.livekit.token_lifetime"));
                CHECK(has_finding(merovingian::config::validate(above.config), "server.rtc.livekit.token_lifetime"));
                CHECK(has_finding(zero.findings, "server.rtc.livekit.token_lifetime"));
                CHECK(has_finding(garbage.findings, "server.rtc.livekit.token_lifetime"));
            }
        }
    }
}

SCENARIO("Every built-in token service key needs a restart", "[config][rtc][livekit]")
{
    GIVEN("two configurations that differ in every token service key")
    {
        auto const before = parse_token_service("");
        auto const after =
            merovingian::config::parse_key_value_config("server.rtc.livekit.url=wss://sfu2.example.org\n"
                                                        "server.rtc.livekit.api_url=https://sfu2.example.org\n"
                                                        "server.rtc.livekit.api_key=APIkey_2\n"
                                                        "server.rtc.livekit.api_secret_file=/etc/merovingian/livekit2\n"
                                                        "server.rtc.livekit.token_lifetime=10m\n");

        WHEN("a reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);

            THEN("each key is named and each needs a restart")
            {
                auto const keys = std::vector<std::string>{
                    "server.rtc.livekit.url", "server.rtc.livekit.api_url", "server.rtc.livekit.api_key",
                    "server.rtc.livekit.api_secret_file", "server.rtc.livekit.token_lifetime"};
                for (auto const& key : keys)
                {
                    INFO(key);
                    CHECK(plan_names(plan, key));
                    CHECK(merovingian::config::reload_policy_for_key(key) ==
                          merovingian::config::ReloadPolicy::restart_required);
                }
            }
        }
    }
}
