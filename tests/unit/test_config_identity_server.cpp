// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |       IDENTITY SERVICE API CONFIGURATION PARSING & VALIDATION TESTS    |
// |                                                                         |
// |  Spec: Matrix Identity Service API v1.19                               |
// |  URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md             |
// +-------------------------------------------------------------------------+

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto contains_finding(std::vector<merovingian::config::ConfigValidationFinding> const& findings,
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

} // namespace

SCENARIO("Identity server config is empty and valid by default", "[config][identity-server]")
{
    GIVEN("a default server configuration")
    {
        auto config = merovingian::config::Config{};

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no identity-server findings are reported and the allowlist is empty")
            {
                REQUIRE(merovingian::config::is_valid(config));
                REQUIRE_FALSE(contains_finding(findings, "server.identity_server.trusted_servers"));
                REQUIRE(config.server().identity_server.trusted_servers.empty());
            }
        }
    }
}

SCENARIO("Identity server config parses the trusted list, bind domains, and timeouts", "[config][identity-server]")
{
    GIVEN("a config string configuring a trusted identity server")
    {
        auto const input =
            std::string{"server.identity_server.trusted_servers=https://is.example.org,https://is2.example.org\n"
                        "server.identity_server.default_server=https://is.example.org\n"
                        "server.identity_server.allowed_bind_domains=example.org,example.com\n"
                        "server.identity_server.connect_timeout_seconds=5\n"
                        "server.identity_server.total_timeout_seconds=20\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("all fields are populated and the configuration is accepted")
            {
                REQUIRE(merovingian::config::is_valid(result.config));
                REQUIRE(result.config.server().identity_server.trusted_servers.size() == 2U);
                REQUIRE(result.config.server().identity_server.trusted_servers[0U] == "https://is.example.org");
                REQUIRE(result.config.server().identity_server.allowed_bind_domains.size() == 2U);
                REQUIRE(result.config.server().identity_server.connect_timeout_seconds == 5U);
                REQUIRE(result.config.server().identity_server.total_timeout_seconds == 20U);
            }
        }
    }
}

SCENARIO("Identity server trusted servers must use HTTPS", "[config][identity-server]")
{
    GIVEN("a config string with a cleartext trusted server")
    {
        auto const input = std::string{"server.identity_server.trusted_servers=http://is.example.org\n"
                                       "server.identity_server.default_server=http://is2.example.org\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("it is rejected with an HTTPS finding")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.identity_server.trusted_servers"));
            }
        }
    }
}

SCENARIO("Identity server total timeout must be at least the connect timeout", "[config][identity-server]")
{
    GIVEN("a config string with total_timeout < connect_timeout")
    {
        auto const input = std::string{"server.identity_server.trusted_servers=https://is.example.org\n"
                                       "server.identity_server.connect_timeout_seconds=30\n"
                                       "server.identity_server.total_timeout_seconds=10\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the timeout ordering finding is reported")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.identity_server.total_timeout_seconds"));
            }
        }
    }
}

SCENARIO("Identity server config changes require a restart", "[config][identity-server][reload]")
{
    GIVEN("identity server config keys")
    {
        auto constexpr trusted = "server.identity_server.trusted_servers";
        auto constexpr bind_domains = "server.identity_server.allowed_bind_domains";
        auto constexpr connect_timeout = "server.identity_server.connect_timeout_seconds";
        auto constexpr total_timeout = "server.identity_server.total_timeout_seconds";

        WHEN("their reload policies are requested")
        {
            THEN("all are restart_required (the IS client and resolver are built at startup)")
            {
                REQUIRE(merovingian::config::reload_policy_for_key(trusted) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(bind_domains) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(connect_timeout) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(total_timeout) ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}

// ADR-0498: a key the code does not act on is removed, so it is refused as unknown rather than accepted and ignored.
SCENARIO("Removed configuration keys are refused as unknown", "[config][identity-server][logging]")
{
    GIVEN("config strings naming keys that nothing reads")
    {
        auto const default_server = std::string{"server.identity_server.default_server=https://is.example.org\n"};
        auto const structured = std::string{"security.logging.structured=true\n"};

        WHEN("each is parsed")
        {
            auto const default_result = merovingian::config::parse_key_value_config(default_server);
            auto const structured_result = merovingian::config::parse_key_value_config(structured);

            THEN("each is a parse finding naming the key")
            {
                REQUIRE(contains_finding(default_result.findings, "server.identity_server.default_server"));
                REQUIRE(contains_finding(structured_result.findings, "security.logging.structured"));
                REQUIRE_FALSE(default_result.findings.empty());
                REQUIRE_FALSE(structured_result.findings.empty());
            }
        }
    }
}

// ADR-0498: tokens and event content are always redacted; only true is accepted.
SCENARIO("A configuration that turns log redaction off is refused", "[config][logging][security]")
{
    GIVEN("config strings that set a redaction key to false")
    {
        auto const tokens = std::string{"security.logging.redact_tokens=false\n"};
        auto const content = std::string{"security.logging.redact_event_content=false\n"};
        auto const safe =
            std::string{"security.logging.redact_tokens=true\nsecurity.logging.redact_event_content=true\n"};

        WHEN("each is parsed and validated")
        {
            auto const tokens_result = merovingian::config::parse_key_value_config(tokens);
            auto const content_result = merovingian::config::parse_key_value_config(content);
            auto const safe_result = merovingian::config::parse_key_value_config(safe);

            THEN("false is refused naming the key, and true is accepted")
            {
                REQUIRE(contains_finding(merovingian::config::validate(tokens_result.config),
                                         "security.logging.redact_tokens"));
                REQUIRE(contains_finding(merovingian::config::validate(content_result.config),
                                         "security.logging.redact_event_content"));
                REQUIRE_FALSE(merovingian::config::is_valid(tokens_result.config));
                REQUIRE_FALSE(merovingian::config::is_valid(content_result.config));
                REQUIRE(merovingian::config::is_valid(safe_result.config));
            }
        }
    }
}

// ADR-0498: an entry that can never equal an email domain would make every email refused with no explanation, so
// configuration says why.
SCENARIO("An allowed_bind_domains entry that can never match is a configuration finding", "[config][identity-server]")
{
    GIVEN("allowed_bind_domains entries with an at sign, a wildcard, whitespace or nothing at all")
    {
        auto const at_sign =
            merovingian::config::parse_key_value_config("server.identity_server.allowed_bind_domains=@example.org\n");
        auto const wildcard =
            merovingian::config::parse_key_value_config("server.identity_server.allowed_bind_domains=*.example.org\n");
        auto const whitespace = merovingian::config::parse_key_value_config(
            "server.identity_server.allowed_bind_domains=example.org,exa mple.com\n");
        auto const good = merovingian::config::parse_key_value_config(
            "server.identity_server.allowed_bind_domains=example.org,Example.com\n");
        auto empty = merovingian::config::Config{};
        empty.server().identity_server.allowed_bind_domains = {"example.org", ""};

        WHEN("each is validated")
        {
            THEN("each bad entry is a finding on the key and plain domains are accepted")
            {
                auto const key = "server.identity_server.allowed_bind_domains";
                REQUIRE(contains_finding(merovingian::config::validate(at_sign.config), key));
                REQUIRE(contains_finding(merovingian::config::validate(wildcard.config), key));
                REQUIRE(contains_finding(merovingian::config::validate(whitespace.config), key));
                REQUIRE(contains_finding(merovingian::config::validate(empty), key));
                REQUIRE_FALSE(contains_finding(merovingian::config::validate(good.config), key));
            }
        }
    }
}
