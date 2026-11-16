// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.turn.uris: several TURN URIs beside the older single server.turn.server (ADR-0821).
// Spec: docs/matrix-v1.19-spec/client-server-api.md, "Voice over IP": `uris` is a list of TURN URIs.

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

[[nodiscard]] auto parse_uris(std::string const& uris) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config("server.turn.uris=" + uris +
                                                       "\nserver.turn.username=u\nserver.turn.password=p\n");
}

} // namespace

SCENARIO("server.turn.uris lists several TURN URIs in order", "[config][turn][turn-uris]")
{
    GIVEN("a UDP, a TCP and a TLS relay and static credentials")
    {
        auto const parsed =
            parse_uris("turn:turn.example.org:3478?transport=udp, turn:turn.example.org:3478?transport=tcp,"
                       "turns:turn.example.org:5349?transport=tcp");

        WHEN("validated")
        {
            THEN("the entries are kept in the configured order and nothing is reported")
            {
                REQUIRE(merovingian::config::is_valid(parsed.config));
                REQUIRE(parsed.findings.empty());
                auto const& uris = parsed.config.server().turn.uris;
                REQUIRE(uris.size() == 3U);
                CHECK(uris[0U] == "turn:turn.example.org:3478?transport=udp");
                CHECK(uris[1U] == "turn:turn.example.org:3478?transport=tcp");
                CHECK(uris[2U] == "turns:turn.example.org:5349?transport=tcp");
                CHECK(parsed.config.server().turn.server.empty());
            }
        }
    }

    GIVEN("only the older server.turn.server key, as a 1.0.x config sets it")
    {
        auto const parsed = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:turn.example.org:3478\nserver.turn.username=u\nserver.turn.password=p\n");

        WHEN("validated")
        {
            THEN("it is accepted unchanged and server.turn.uris stays empty")
            {
                REQUIRE(merovingian::config::is_valid(parsed.config));
                CHECK(parsed.config.server().turn.server == "turn:turn.example.org:3478");
                CHECK(parsed.config.server().turn.uris.empty());
            }
        }
    }

    GIVEN("server.turn.uris with a shared secret file and no username or password")
    {
        auto const parsed = merovingian::config::parse_key_value_config(
            "server.turn.uris=turn:t.example.org\nserver.turn.shared_secret_file=/run/secrets/turn\n");

        WHEN("validated")
        {
            THEN("the list alone enables TURN, so nothing is reported")
            {
                REQUIRE(merovingian::config::is_valid(parsed.config));
            }
        }
    }
}

SCENARIO("server.turn.uris accepts the RFC 7065 forms and refuses everything else", "[config][turn][turn-uris]")
{
    GIVEN("entries that follow the TURN URI grammar")
    {
        THEN("each is accepted")
        {
            for (auto const* good :
                 {"turn:turn.example.org", "turn:turn.example.org:3478", "turn:turn.example.org:3478?transport=udp",
                  "turns:turn.example.org:5349?transport=tcp", "turn:192.0.2.1:3478", "turn:[2001:db8::1]:3478",
                  "turn:[::1]", "turn:[::ffff:192.0.2.1]:3478?transport=tcp", "turn:[2001:db8::1]",
                  "turn:a-b.example.org:65535", "turn:turn.example.org:1?transport=tcp"})
            {
                INFO(good);
                auto const parsed = parse_uris(good);
                REQUIRE(merovingian::config::is_valid(parsed.config));
                REQUIRE_FALSE(has_finding(parsed.findings, "server.turn.uris"));
            }
        }
    }

    GIVEN("entries with no host, or that leave the grammar")
    {
        THEN("each is refused")
        {
            for (auto const* bad : {"turn:?transport=udp",
                                    "turn::3478",
                                    "turn:@x",
                                    "turns:/x",
                                    "turn:turn.example.org:",
                                    "turn:turn.example.org:0",
                                    "turn:turn.example.org:65536",
                                    "turn:turn.example.org:+3478",
                                    "turn:turn.example.org:34a8",
                                    "turn:turn.example.org:3478?transport=sctp",
                                    "turn:turn.example.org:3478?transport=udp&x=1",
                                    "turn:turn.example.org:3478?x=1",
                                    "turn:turn.example.org:3478?transport=",
                                    "turn:turn.example.org:3478?transport=udp?x",
                                    "turn:turn.example.org.",
                                    "turn:.example.org",
                                    "turn:-example.org",
                                    "turn:example.org-",
                                    "turn:u@turn.example.org",
                                    "turn:turn.example.org/path",
                                    "turn:turn.example.org#frag",
                                    "turn:turn.example.org:3478#frag",
                                    "turn:turn_example.org",
                                    "turn:[2001:db8::1",
                                    "turn:2001:db8::1]:3478",
                                    "turn:[]:3478",
                                    "turn:[2001:db8::g]:3478",
                                    "turn:[2001:db8::1]x",
                                    "turn:[2001:db8::1]:",
                                    "turn:[example.org]",
                                    "turn:[:]",
                                    "turn:[::::]",
                                    "turn:[12345::1]",
                                    "turn:[]",
                                    "turn:[::1",
                                    "turn:[fe80::1%eth0]"})
            {
                INFO(bad);
                auto const parsed = parse_uris(std::string{"turn:ok.example.org,"} + bad);
                REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
                REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
            }
        }
    }
}

SCENARIO("server.turn.uris uses the config's ordinary comma-separated list syntax", "[config][turn][turn-uris]")
{
    GIVEN("a list with an empty entry between two URIs")
    {
        auto const parsed = parse_uris("turn:a.example,,turn:b.example");

        THEN("the empty entry is ignored")
        {
            REQUIRE(merovingian::config::is_valid(parsed.config));
            REQUIRE(parsed.config.server().turn.uris.size() == 2U);
            CHECK(parsed.config.server().turn.uris[0U] == "turn:a.example");
            CHECK(parsed.config.server().turn.uris[1U] == "turn:b.example");
        }
    }

    GIVEN("a list with a trailing comma and whitespace around entries")
    {
        auto const parsed = parse_uris("  turn:a.example ,\tturn:b.example , ");

        THEN("whitespace around an entry and the empty last entry are ignored")
        {
            REQUIRE(merovingian::config::is_valid(parsed.config));
            REQUIRE(parsed.config.server().turn.uris.size() == 2U);
            CHECK(parsed.config.server().turn.uris[0U] == "turn:a.example");
            CHECK(parsed.config.server().turn.uris[1U] == "turn:b.example");
        }
    }

    GIVEN("a value of only a comma")
    {
        auto const parsed = merovingian::config::parse_key_value_config("server.turn.uris=,\n");

        THEN("the list is empty and TURN is not configured")
        {
            REQUIRE(merovingian::config::is_valid(parsed.config));
            CHECK(parsed.config.server().turn.uris.empty());
        }
    }
}

SCENARIO("server.turn.uris refuses a bad list and never repairs it", "[config][turn][turn-uris]")
{
    GIVEN("both server.turn.server and server.turn.uris")
    {
        auto const parsed = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:a.example.org\nserver.turn.uris=turn:b.example.org\n"
            "server.turn.username=u\nserver.turn.password=p\n");

        THEN("the configuration is refused naming server.turn.uris")
        {
            REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
            REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
        }
    }

    GIVEN("an entry with a scheme other than turn: or turns:")
    {
        THEN("each is refused")
        {
            for (auto const* bad : {"https://t.example.org", "stun:t.example.org", "TURN:t.example.org",
                                    "turn.example.org:3478", "turn:"})
            {
                INFO(bad);
                auto const parsed = parse_uris(std::string{"turn:ok.example.org,"} + bad);
                REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
                REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
            }
        }
    }

    GIVEN("an entry holding whitespace or a control character")
    {
        auto const inner_space = parse_uris("turn:a b.example.org");
        auto const tab = parse_uris("turn:a\tb.example.org");
        auto const bell = parse_uris("turn:a\x07.example.org");
        auto const high = parse_uris("turn:caf\xC3\xA9.example.org");

        THEN("each is refused")
        {
            for (auto const* parsed : {&inner_space, &tab, &bell, &high})
            {
                REQUIRE_FALSE(merovingian::config::is_valid(parsed->config));
                REQUIRE(has_finding(parsed->findings, "server.turn.uris"));
            }
        }
    }

    GIVEN("an entry longer than 512 bytes")
    {
        auto const longest = "turn:" + std::string(507U, 'a');
        auto const too_long = "turn:" + std::string(508U, 'a');

        THEN("512 bytes is accepted and 513 is refused")
        {
            REQUIRE(merovingian::config::is_valid(parse_uris(longest).config));
            auto const parsed = parse_uris(too_long);
            REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
            REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
        }
    }

    GIVEN("more than 16 entries")
    {
        auto list = std::string{};
        auto const build = [&list](int count) {
            list.clear();
            for (int i = 0; i < count; ++i)
            {
                list += (i == 0 ? "" : ",");
                list += "turn:t" + std::to_string(i) + ".example.org";
            }
        };

        THEN("16 are accepted and 17 are refused")
        {
            build(16);
            REQUIRE(merovingian::config::is_valid(parse_uris(list).config));
            build(17);
            auto const parsed = parse_uris(list);
            REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
            REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
        }
    }

    GIVEN("the same entry twice")
    {
        auto const parsed = parse_uris("turn:t.example.org,turns:t.example.org,turn:t.example.org");

        THEN("the configuration is refused")
        {
            REQUIRE_FALSE(merovingian::config::is_valid(parsed.config));
            REQUIRE(has_finding(parsed.findings, "server.turn.uris"));
        }
    }

    GIVEN("server.turn.uris set but credentials missing")
    {
        auto const parsed = merovingian::config::parse_key_value_config("server.turn.uris=turn:t.example.org\n");

        THEN("the missing username and password are reported, as for server.turn.server")
        {
            REQUIRE(has_finding(parsed.findings, "server.turn.username"));
            REQUIRE(has_finding(parsed.findings, "server.turn.password"));
        }
    }
}

SCENARIO("server.turn.uris is reloadable and diffed like the other server.turn keys", "[config][turn][turn-uris]")
{
    GIVEN("two configurations that differ only in server.turn.uris")
    {
        auto const before = parse_uris("turn:a.example.org");
        auto const after = parse_uris("turn:a.example.org,turns:a.example.org");

        WHEN("a reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);

            THEN("the key is reported and needs no restart")
            {
                bool found = false;
                for (auto const& change : plan.changes())
                {
                    found = found || change.key == "server.turn.uris";
                }
                CHECK(found);
                CHECK(merovingian::config::reload_policy_for_key("server.turn.uris") ==
                      merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}
