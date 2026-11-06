// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// is_loopback_ip_literal: the one definition of "loopback" shared by the SMTP relay check (ADR-0220) and
// the appservice cleartext rule (ADR-0515). Only an IP literal counts; a name such as `localhost` never does.

#include "merovingian/net/loopback_literal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

SCENARIO("Loopback IP literals are recognised", "[net][loopback]")
{
    GIVEN("IPv4 addresses inside 127.0.0.0/8 and IPv6 ::1 in several spellings")
    {
        auto const accepted = {"127.0.0.1", "127.5.6.7",         "127.255.255.254", "::1",
                               "[::1]",     "[0:0:0:0:0:0:0:1]", "0:0:0:0:0:0:0:1", "[0000::0001]"};

        WHEN("each is tested")
        {
            THEN("each is a loopback literal")
            {
                for (auto const* host : accepted)
                {
                    INFO(host);
                    REQUIRE(merovingian::net::is_loopback_ip_literal(host));
                }
            }
        }
    }
}

SCENARIO("Names, other addresses and malformed text are not loopback literals", "[net][loopback][security]")
{
    GIVEN("hosts that resolve to loopback by name, other addresses, and garbage")
    {
        auto const refused = {"localhost",
                              "LOCALHOST",
                              "128.0.0.1",
                              "126.255.255.255",
                              "10.0.0.1",
                              "::2",
                              "::",
                              "[::2]",
                              "[::1",
                              "::1]",
                              "[[::1]]",
                              "",
                              "[]",
                              "garbage",
                              "127.1",
                              "127.0.0.1.",
                              "127.0.0.1:80",
                              " 127.0.0.1",
                              "::ffff:127.0.0.1",
                              "[::1]:80",
                              "0x7f.0.0.1",
                              "127.0.0.256"};

        WHEN("each is tested")
        {
            THEN("none is a loopback literal")
            {
                for (auto const* host : refused)
                {
                    INFO(host);
                    REQUIRE_FALSE(merovingian::net::is_loopback_ip_literal(host));
                }
            }
        }
    }
}
