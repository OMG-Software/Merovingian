// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Configuration parsing, validation and reload classification for server.email.* (email pushers).

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::config::ConfigValidationFinding;

[[nodiscard]] auto contains_finding(std::vector<ConfigValidationFinding> const& findings, std::string_view field)
    -> bool
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

[[nodiscard]] auto parse(std::string const& input) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config(input);
}

// A complete, valid relay over implicit TLS; tests append overrides after it.
[[nodiscard]] auto smtps_base() -> std::string
{
    return std::string{"server.email.smtp_url=smtps://smtp.example.org\n"
                       "server.email.from=noreply@example.org\n"};
}

} // namespace

SCENARIO("Email config is off and valid by default", "[config][email]")
{
    GIVEN("a default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("email pushers are off, the defaults are the documented ones and nothing is reported")
            {
                auto const& email = config.server().email;
                REQUIRE(email.smtp_url.empty());
                REQUIRE(email.require_tls);
                REQUIRE(email.from.empty());
                REQUIRE(email.username.empty());
                REQUIRE(email.password_file.empty());
                REQUIRE(email.connect_timeout_seconds == 10U);
                REQUIRE(email.total_timeout_seconds == 30U);
                REQUIRE(email.notification_delay_seconds == 600U);
                REQUIRE(email.notification_throttle_seconds == 3600U);
                REQUIRE(findings.empty());
                REQUIRE(merovingian::config::is_valid(config));
            }
        }
    }
}

SCENARIO("Every server.email key parses into its field", "[config][email]")
{
    GIVEN("a config text setting every email key")
    {
        auto const input = std::string{"server.email.smtp_url=smtps://smtp.example.org:2465\n"
                                       "server.email.require_tls=true\n"
                                       "server.email.from=noreply@example.org\n"
                                       "server.email.username=mailer\n"
                                       "server.email.password_file=/etc/merovingian/smtp.pw\n"
                                       "server.email.connect_timeout_seconds=5\n"
                                       "server.email.total_timeout_seconds=20\n"
                                       "server.email.notification_delay_seconds=0\n"
                                       "server.email.notification_throttle_seconds=0\n"};

        WHEN("parsed")
        {
            auto const result = parse(input);

            THEN("each field holds its value and the configuration is accepted")
            {
                auto const& email = result.config.server().email;
                REQUIRE(email.smtp_url == "smtps://smtp.example.org:2465");
                REQUIRE(email.require_tls);
                REQUIRE(email.from == "noreply@example.org");
                REQUIRE(email.username == "mailer");
                REQUIRE(email.password_file == "/etc/merovingian/smtp.pw");
                REQUIRE(email.connect_timeout_seconds == 5U);
                REQUIRE(email.total_timeout_seconds == 20U);
                REQUIRE(email.notification_delay_seconds == 0U);
                REQUIRE(email.notification_throttle_seconds == 0U);
                REQUIRE(result.findings.empty());
            }
        }
    }

    GIVEN("a config text setting require_tls to false")
    {
        WHEN("parsed")
        {
            auto const result = parse("server.email.require_tls=false\n");

            THEN("the field is false")
            {
                REQUIRE_FALSE(result.config.server().email.require_tls);
            }
        }
    }
}

SCENARIO("Email keys reject values of the wrong shape at parse time", "[config][email]")
{
    GIVEN("a non-boolean require_tls")
    {
        WHEN("parsed")
        {
            auto const result = parse("server.email.require_tls=maybe\n");

            THEN("a finding names the key and the default is kept")
            {
                REQUIRE(contains_finding(result.findings, "server.email.require_tls"));
                REQUIRE(result.config.server().email.require_tls);
            }
        }
    }

    GIVEN("a zero or non-numeric timeout")
    {
        WHEN("parsed")
        {
            auto const zero_connect = parse("server.email.connect_timeout_seconds=0\n");
            auto const zero_total = parse("server.email.total_timeout_seconds=0\n");
            auto const garbage_connect = parse("server.email.connect_timeout_seconds=soon\n");
            auto const garbage_total = parse("server.email.total_timeout_seconds=-5\n");

            THEN("each is a finding and the defaults are kept")
            {
                REQUIRE(contains_finding(zero_connect.findings, "server.email.connect_timeout_seconds"));
                REQUIRE(contains_finding(zero_total.findings, "server.email.total_timeout_seconds"));
                REQUIRE(contains_finding(garbage_connect.findings, "server.email.connect_timeout_seconds"));
                REQUIRE(contains_finding(garbage_total.findings, "server.email.total_timeout_seconds"));
                REQUIRE(zero_connect.config.server().email.connect_timeout_seconds == 10U);
                REQUIRE(zero_total.config.server().email.total_timeout_seconds == 30U);
            }
        }
    }

    GIVEN("a non-numeric or negative delay or throttle")
    {
        WHEN("parsed")
        {
            auto const garbage_delay = parse("server.email.notification_delay_seconds=later\n");
            auto const negative_throttle = parse("server.email.notification_throttle_seconds=-1\n");

            THEN("each is a finding and the defaults are kept")
            {
                REQUIRE(contains_finding(garbage_delay.findings, "server.email.notification_delay_seconds"));
                REQUIRE(contains_finding(negative_throttle.findings, "server.email.notification_throttle_seconds"));
                REQUIRE(garbage_delay.config.server().email.notification_delay_seconds == 600U);
                REQUIRE(negative_throttle.config.server().email.notification_throttle_seconds == 3600U);
            }
        }
    }
}

SCENARIO("A relay over implicit TLS with credentials is accepted", "[config][email]")
{
    GIVEN("an smtps relay with a username and a password file")
    {
        auto const input = smtps_base() + "server.email.username=mailer\nserver.email.password_file=/etc/smtp.pw\n";

        WHEN("parsed and validated")
        {
            auto const result = parse(input);

            THEN("there are no findings")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(merovingian::config::is_valid(result.config));
            }
        }
    }

    GIVEN("an smtp STARTTLS relay with no credentials")
    {
        WHEN("parsed and validated")
        {
            auto const result =
                parse("server.email.smtp_url=smtp://mail.example.org:25\nserver.email.from=a@example.org\n");

            THEN("there are no findings")
            {
                REQUIRE(result.findings.empty());
            }
        }
    }
}

SCENARIO("smtp_url must be a plain relay URL", "[config][email]")
{
    GIVEN("urls with a wrong scheme, userinfo, a path or an out-of-range port")
    {
        WHEN("each is validated")
        {
            auto const http = parse("server.email.smtp_url=http://smtp.example.org\nserver.email.from=a@example.org\n");
            auto const userinfo =
                parse("server.email.smtp_url=smtps://user:pw@smtp.example.org\nserver.email.from=a@example.org\n");
            auto const path =
                parse("server.email.smtp_url=smtps://smtp.example.org/relay\nserver.email.from=a@example.org\n");
            auto const port =
                parse("server.email.smtp_url=smtps://smtp.example.org:70000\nserver.email.from=a@example.org\n");

            THEN("each is a finding on smtp_url")
            {
                REQUIRE(contains_finding(http.findings, "server.email.smtp_url"));
                REQUIRE(contains_finding(userinfo.findings, "server.email.smtp_url"));
                REQUIRE(contains_finding(path.findings, "server.email.smtp_url"));
                REQUIRE(contains_finding(port.findings, "server.email.smtp_url"));
                REQUIRE_FALSE(merovingian::config::is_valid(http.config));
            }
        }
    }

    GIVEN("a url carrying a password in its userinfo")
    {
        WHEN("validated")
        {
            auto const result =
                parse("server.email.smtp_url=smtps://user:hunter2@smtp.example.org\nserver.email.from=a@example.org\n");

            THEN("no finding message repeats the password")
            {
                for (auto const& finding : result.findings)
                {
                    REQUIRE(finding.message.find("hunter2") == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("from must be a safe plain address when a relay is set", "[config][email]")
{
    GIVEN("a relay with no from")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtps://smtp.example.org\n");

            THEN("from is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.from"));
            }
        }
    }

    GIVEN("a relay with a display-name or injected from")
    {
        WHEN("validated")
        {
            auto const display = parse(smtps_base() + "server.email.from=Name <noreply@example.org>\n");
            auto const no_at = parse(smtps_base() + "server.email.from=noreply\n");

            THEN("from is a finding")
            {
                REQUIRE(contains_finding(display.findings, "server.email.from"));
                REQUIRE(contains_finding(no_at.findings, "server.email.from"));
            }
        }
    }

    GIVEN("no relay and a malformed from")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.from=not an address\n");

            THEN("nothing about from is reported, because email is off")
            {
                REQUIRE_FALSE(contains_finding(result.findings, "server.email.from"));
                REQUIRE(merovingian::config::is_valid(result.config));
            }
        }
    }
}

SCENARIO("username and password_file are set together", "[config][email]")
{
    GIVEN("a relay with a username and no password file")
    {
        WHEN("validated")
        {
            auto const result = parse(smtps_base() + "server.email.username=mailer\n");

            THEN("password_file is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.password_file"));
            }
        }
    }

    GIVEN("a relay with a password file and no username")
    {
        WHEN("validated")
        {
            auto const result = parse(smtps_base() + "server.email.password_file=/etc/smtp.pw\n");

            THEN("password_file is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.password_file"));
            }
        }
    }

    GIVEN("no relay and a username alone")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.username=mailer\n");

            THEN("nothing is reported, because email is off")
            {
                REQUIRE_FALSE(contains_finding(result.findings, "server.email.password_file"));
            }
        }
    }
}

SCENARIO("username is printable ASCII without spaces and at most 256 bytes", "[config][email]")
{
    GIVEN("usernames with a space, a control byte and excess length")
    {
        auto const base = smtps_base() + "server.email.password_file=/etc/smtp.pw\n";

        WHEN("validated")
        {
            auto const with_space = parse(base + "server.email.username=mail er\n");
            auto const with_control = parse(base + "server.email.username=mail\ter\n");
            auto const too_long = parse(base + "server.email.username=" + std::string(257U, 'u') + "\n");
            auto const at_limit = parse(base + "server.email.username=" + std::string(256U, 'u') + "\n");

            THEN("only the 256 byte name is accepted")
            {
                REQUIRE(contains_finding(with_space.findings, "server.email.username"));
                REQUIRE(contains_finding(with_control.findings, "server.email.username"));
                REQUIRE(contains_finding(too_long.findings, "server.email.username"));
                REQUIRE_FALSE(contains_finding(at_limit.findings, "server.email.username"));
            }
        }
    }
}

// ADR-0220: cleartext SMTP is allowed only to a relay on this machine, named by a loopback IP literal
// (DNS decides where a name goes), and never with credentials.
SCENARIO("require_tls=false is allowed for a cleartext loopback relay without credentials", "[config][email]")
{
    GIVEN("a cleartext smtp relay at a loopback IPv4 literal with no credentials")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtp://127.0.0.1:25\n"
                                      "server.email.from=noreply@example.org\n"
                                      "server.email.require_tls=false\n");

            THEN("there are no findings")
            {
                REQUIRE(result.findings.empty());
                REQUIRE_FALSE(result.config.server().email.require_tls);
            }
        }
    }

    GIVEN("a cleartext smtp relay at the IPv6 loopback literal")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtp://[::1]:25\n"
                                      "server.email.from=noreply@example.org\n"
                                      "server.email.require_tls=false\n");

            THEN("there are no findings")
            {
                REQUIRE(result.findings.empty());
            }
        }
    }

    GIVEN("require_tls=false and no relay")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.require_tls=false\n");

            THEN("nothing is reported, because email is off")
            {
                REQUIRE_FALSE(contains_finding(result.findings, "server.email.require_tls"));
            }
        }
    }
}

// The same rule, from the other side: every cleartext configuration it does not allow is a finding.
SCENARIO("require_tls=false is refused for a remote, named or implicit-TLS relay, or with credentials",
         "[config][email]")
{
    GIVEN("a cleartext smtp relay at a remote host name")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtp://mail.example.org\n"
                                      "server.email.from=noreply@example.org\n"
                                      "server.email.require_tls=false\n");

            THEN("require_tls is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.require_tls"));
            }
        }
    }

    GIVEN("a cleartext smtp relay at the name localhost")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtp://localhost\n"
                                      "server.email.from=noreply@example.org\n"
                                      "server.email.require_tls=false\n");

            THEN("require_tls is a finding, because a name is not a loopback literal")
            {
                REQUIRE(contains_finding(result.findings, "server.email.require_tls"));
            }
        }
    }

    GIVEN("an smtps relay with require_tls=false")
    {
        WHEN("validated")
        {
            auto const result = parse(smtps_base() + "server.email.require_tls=false\n");

            THEN("require_tls is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.require_tls"));
            }
        }
    }

    GIVEN("credentials on a loopback cleartext relay")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.smtp_url=smtp://127.0.0.1\n"
                                      "server.email.from=noreply@example.org\n"
                                      "server.email.require_tls=false\n"
                                      "server.email.username=mailer\n"
                                      "server.email.password_file=/etc/smtp.pw\n");

            THEN("username is a finding, because credentials are never sent without TLS")
            {
                REQUIRE(contains_finding(result.findings, "server.email.username"));
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
            }
        }
    }
}

SCENARIO("Email timeouts and intervals are range checked whether or not a relay is set", "[config][email]")
{
    GIVEN("timeouts outside their ranges")
    {
        WHEN("validated with no relay")
        {
            auto const connect_high = parse("server.email.connect_timeout_seconds=301\n"
                                            "server.email.total_timeout_seconds=600\n");
            auto const total_high = parse("server.email.total_timeout_seconds=601\n");

            THEN("each is a finding on its own key")
            {
                REQUIRE(contains_finding(connect_high.findings, "server.email.connect_timeout_seconds"));
                REQUIRE(contains_finding(total_high.findings, "server.email.total_timeout_seconds"));
            }
        }
    }

    GIVEN("timeouts at the top of their ranges")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.connect_timeout_seconds=300\n"
                                      "server.email.total_timeout_seconds=600\n");

            THEN("there are no findings")
            {
                REQUIRE(result.findings.empty());
            }
        }
    }

    GIVEN("a total timeout below the connect timeout")
    {
        WHEN("validated")
        {
            auto const result = parse("server.email.connect_timeout_seconds=30\n"
                                      "server.email.total_timeout_seconds=10\n");

            THEN("total_timeout_seconds is a finding")
            {
                REQUIRE(contains_finding(result.findings, "server.email.total_timeout_seconds"));
            }
        }
    }

    GIVEN("a delay and a throttle beyond their maxima")
    {
        WHEN("validated")
        {
            auto const delay = parse("server.email.notification_delay_seconds=86401\n");
            auto const throttle = parse("server.email.notification_throttle_seconds=604801\n");
            auto const at_limits = parse("server.email.notification_delay_seconds=86400\n"
                                         "server.email.notification_throttle_seconds=604800\n");

            THEN("only values above the maxima are findings")
            {
                REQUIRE(contains_finding(delay.findings, "server.email.notification_delay_seconds"));
                REQUIRE(contains_finding(throttle.findings, "server.email.notification_throttle_seconds"));
                REQUIRE(at_limits.findings.empty());
            }
        }
    }
}

SCENARIO("Every server.email key needs a restart to change", "[config][email][reload]")
{
    GIVEN("each email key")
    {
        auto const keys = std::vector<std::string>{"server.email.smtp_url",
                                                   "server.email.require_tls",
                                                   "server.email.from",
                                                   "server.email.username",
                                                   "server.email.password_file",
                                                   "server.email.connect_timeout_seconds",
                                                   "server.email.total_timeout_seconds",
                                                   "server.email.notification_delay_seconds",
                                                   "server.email.notification_throttle_seconds"};

        WHEN("their reload policies are requested")
        {
            THEN("all are restart_required")
            {
                for (auto const& key : keys)
                {
                    REQUIRE(merovingian::config::reload_policy_for_key(key) ==
                            merovingian::config::ReloadPolicy::restart_required);
                }
            }
        }
    }

    GIVEN("two configs differing in every email field")
    {
        auto const current = merovingian::config::Config{};
        auto const next = parse("server.email.smtp_url=smtps://smtp.example.org\n"
                                "server.email.require_tls=false\n"
                                "server.email.from=noreply@example.org\n"
                                "server.email.username=mailer\n"
                                "server.email.password_file=/etc/smtp.pw\n"
                                "server.email.connect_timeout_seconds=11\n"
                                "server.email.total_timeout_seconds=31\n"
                                "server.email.notification_delay_seconds=601\n"
                                "server.email.notification_throttle_seconds=3601\n")
                              .config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("each field is a restart-required change, and no value appears in the plan")
            {
                REQUIRE(plan.restart_required_change_count() == 9U);
                REQUIRE(plan.reloadable_change_count() == 0U);
                auto const summary = merovingian::config::reload_plan_summary(plan);
                REQUIRE(summary.find("smtp.example.org") == std::string::npos);
                REQUIRE(summary.find("/etc/smtp.pw") == std::string::npos);
                for (auto const& change : plan.changes())
                {
                    REQUIRE(change.key.rfind("server.email.", 0U) == 0U);
                    REQUIRE(change.key.find("smtp.example.org") == std::string::npos);
                }
            }
        }
    }

    GIVEN("two identical email configs")
    {
        auto const current = parse(smtps_base()).config;
        auto const next = parse(smtps_base()).config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("no email change is recorded")
            {
                REQUIRE_FALSE(plan.has_changes());
            }
        }
    }
}
