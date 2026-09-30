// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/receipt_visibility.hpp"

#include <catch2/catch_test_macros.hpp>

// Spec (C-S API, Receipts): "Servers MUST NOT send the m.read.private receipt to any other
// user than the one which originally sent it." and "m.fully_read does not appear under
// m.receipt".
SCENARIO("Receipt visibility decides which members may see a stored receipt", "[sync][receipts][security][csaz-4]")
{
    using merovingian::sync::receipt_visible_to;

    GIVEN("a public m.read receipt sent by alice")
    {
        WHEN("a viewer is checked")
        {
            THEN("alice and other members can see it")
            {
                REQUIRE(receipt_visible_to("m.read", "@alice:example.org", "@alice:example.org"));
                REQUIRE(receipt_visible_to("m.read", "@alice:example.org", "@bob:example.org"));
            }
        }
    }

    GIVEN("a private m.read.private receipt sent by alice")
    {
        WHEN("a viewer is checked")
        {
            THEN("only alice can see it")
            {
                REQUIRE(receipt_visible_to("m.read.private", "@alice:example.org", "@alice:example.org"));
                REQUIRE_FALSE(receipt_visible_to("m.read.private", "@alice:example.org", "@bob:example.org"));
            }

            THEN("a viewer whose ID merely resembles the owner cannot see it")
            {
                REQUIRE_FALSE(receipt_visible_to("m.read.private", "@alice:example.org", "@alice:example.com"));
                REQUIRE_FALSE(receipt_visible_to("m.read.private", "@alice:example.org", "@Alice:example.org"));
                REQUIRE_FALSE(receipt_visible_to("m.read.private", "@alice:example.org", ""));
            }
        }
    }

    GIVEN("an m.fully_read marker for alice")
    {
        WHEN("a viewer is checked")
        {
            THEN("it is never part of an m.receipt event, not even for its owner")
            {
                REQUIRE_FALSE(receipt_visible_to("m.fully_read", "@alice:example.org", "@alice:example.org"));
                REQUIRE_FALSE(receipt_visible_to("m.fully_read", "@alice:example.org", "@bob:example.org"));
            }
        }
    }

    GIVEN("a receipt of a type the server does not know")
    {
        WHEN("a viewer is checked")
        {
            THEN("it is withheld from everyone (fail closed)")
            {
                REQUIRE_FALSE(receipt_visible_to("m.something.new", "@alice:example.org", "@alice:example.org"));
                REQUIRE_FALSE(receipt_visible_to("m.something.new", "@alice:example.org", "@bob:example.org"));
                REQUIRE_FALSE(receipt_visible_to("", "@alice:example.org", "@bob:example.org"));
            }
        }
    }
}
