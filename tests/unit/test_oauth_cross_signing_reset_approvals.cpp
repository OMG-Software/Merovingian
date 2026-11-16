// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0797: the cross-signing reset approvals the account page grants. One per user, ten minutes, taken by one
// replacing upload and given back when that upload is not stored, bounded.

#include "merovingian/homeserver/CrossSigningResetApprovals.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using merovingian::homeserver::CrossSigningResetApprovals;

constexpr auto start_ms = std::uint64_t{9'000'000U};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

} // namespace

SCENARIO("A cross-signing reset approval lives ten minutes and is taken once", "[oauth][oauth-reset-approval]")
{
    GIVEN("an approval of alice")
    {
        auto approvals = CrossSigningResetApprovals{};
        REQUIRE(approvals.approve(alice, start_ms));

        WHEN("it is read, taken twice, and read at its end")
        {
            auto const held_before_end =
                approvals.holds(alice, start_ms + CrossSigningResetApprovals::lifetime_ms - 1U);
            auto const bob_holds = approvals.holds(bob, start_ms + 1U);
            auto const first = approvals.take(alice, start_ms + 1U);
            auto const second = approvals.take(alice, start_ms + 2U);

            THEN("it is alice's alone, the first take returns its expiry and the second finds nothing")
            {
                CHECK(held_before_end);
                CHECK_FALSE(bob_holds);
                REQUIRE(first.has_value());
                CHECK(*first == start_ms + CrossSigningResetApprovals::lifetime_ms);
                CHECK_FALSE(second.has_value());
                CHECK(approvals.size() == 0U);
            }
        }

        WHEN("it is read at its end")
        {
            auto const held = approvals.holds(alice, start_ms + CrossSigningResetApprovals::lifetime_ms);
            auto const taken = approvals.take(alice, start_ms + CrossSigningResetApprovals::lifetime_ms);

            THEN("it has expired")
            {
                CHECK_FALSE(held);
                CHECK_FALSE(taken.has_value());
            }
        }
    }
}

SCENARIO("A taken approval goes back only while it is live and the user has not approved again",
         "[oauth][oauth-reset-approval]")
{
    GIVEN("an approval of alice taken by an upload")
    {
        auto approvals = CrossSigningResetApprovals{};
        REQUIRE(approvals.approve(alice, start_ms));
        auto const expiry = approvals.take(alice, start_ms + 1U);
        REQUIRE(expiry.has_value());

        WHEN("the upload is refused and gives it back")
        {
            approvals.restore(alice, *expiry, start_ms + 2U);

            THEN("alice holds it again with its first expiry")
            {
                CHECK(approvals.holds(alice, start_ms + 3U));
                CHECK(approvals.take(alice, start_ms + 3U) == expiry);
            }
        }

        WHEN("it is given back after its expiry")
        {
            approvals.restore(alice, *expiry, *expiry);

            THEN("nothing is held")
            {
                CHECK_FALSE(approvals.holds(alice, *expiry));
                CHECK(approvals.size() == 0U);
            }
        }

        WHEN("alice approves again before the upload gives it back")
        {
            REQUIRE(approvals.approve(alice, start_ms + 100U));
            approvals.restore(alice, *expiry, start_ms + 101U);

            THEN("the newer approval stays")
            {
                CHECK(approvals.take(alice, start_ms + 102U) ==
                      start_ms + 100U + CrossSigningResetApprovals::lifetime_ms);
            }
        }
    }
}

SCENARIO("An approval is withdrawn, replaced by a newer one, and bounded", "[oauth][oauth-reset-approval]")
{
    GIVEN("approvals of alice and bob")
    {
        auto approvals = CrossSigningResetApprovals{};
        REQUIRE(approvals.approve(alice, start_ms));
        REQUIRE(approvals.approve(bob, start_ms));

        WHEN("alice's is withdrawn and bob approves again")
        {
            approvals.withdraw(alice);
            REQUIRE(approvals.approve(bob, start_ms + 50U));

            THEN("alice holds none and bob one, with the later expiry")
            {
                CHECK_FALSE(approvals.holds(alice, start_ms + 1U));
                CHECK(approvals.size() == 1U);
                CHECK(approvals.take(bob, start_ms + 51U) == start_ms + 50U + CrossSigningResetApprovals::lifetime_ms);
            }
        }
    }

    GIVEN("max_approvals approvals of other users")
    {
        auto approvals = CrossSigningResetApprovals{};
        for (auto index = std::size_t{0U}; index < CrossSigningResetApprovals::max_approvals; ++index)
        {
            REQUIRE(approvals.approve("@user" + std::to_string(index) + ":example.org", start_ms));
        }

        WHEN("alice approves while they live, then after they expire, and an empty user approves")
        {
            auto const refused = approvals.approve(alice, start_ms + 1U);
            auto const repeat = approvals.approve("@user0:example.org", start_ms + 1U);
            auto const empty = approvals.approve({}, start_ms + 1U);
            auto const later = approvals.approve(alice, start_ms + CrossSigningResetApprovals::lifetime_ms);

            THEN("a new user is refused at the cap, a held user may approve again, and the cap frees on expiry")
            {
                CHECK_FALSE(refused);
                CHECK(repeat);
                CHECK_FALSE(empty);
                CHECK(later);
                CHECK(approvals.holds(alice, start_ms + CrossSigningResetApprovals::lifetime_ms));
            }
        }
    }
}
