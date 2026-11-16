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
        auto const parsed = merovingian::config::parse_key_value_config("");

        THEN("no transport is configured and nothing is reported")
        {
            CHECK(parsed.config.server().rtc.livekit_service_url.empty());
            CHECK_FALSE(has_finding(parsed.findings, "server.rtc.livekit.service_url"));
        }
    }

    GIVEN("a valid https URL, with a port and a path")
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
            long_url,
        };

        THEN("each is refused with a finding on the key, and is never repaired")
        {
            for (auto const& url : bad)
            {
                INFO(url.substr(0U, 60U));
                auto const parsed = parse_url(url);
                REQUIRE(has_finding(parsed.findings, "server.rtc.livekit.service_url"));
                REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
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
