// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  AUDIT CATEGORY LOOKUP                                                    |
// |                                                                         |
// |  These scenarios cover the inverse of `audit_category_name`. The HTTP   |
// |  audit-filter handler turns `?category=<name>` query parameters into    |
// |  the `AuditCategory` enum, and the operator-visible 400 on unknown     |
// |  names depends on the lookup returning `std::nullopt` for them rather  |
// |  than silently dropping the request.                                   |
// +-------------------------------------------------------------------------+

#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string_view>

SCENARIO("audit_category_from_name maps every known category name back to its enum value",
         "[observability][audit]")
{
    GIVEN("the set of canonical audit category names")
    {
        WHEN("each name is round-tripped through the lookup")
        {
            auto const auth = merovingian::observability::audit_category_from_name("auth");
            auto const key_lifecycle =
                merovingian::observability::audit_category_from_name("key_lifecycle");
            auto const policy = merovingian::observability::audit_category_from_name("policy");
            auto const moderation =
                merovingian::observability::audit_category_from_name("moderation");
            auto const admin = merovingian::observability::audit_category_from_name("admin");

            THEN("the lookup returns the matching enum value and the round-trip is stable")
            {
                REQUIRE(auth == merovingian::observability::AuditCategory::auth);
                REQUIRE(key_lifecycle == merovingian::observability::AuditCategory::key_lifecycle);
                REQUIRE(policy == merovingian::observability::AuditCategory::policy);
                REQUIRE(moderation == merovingian::observability::AuditCategory::moderation);
                REQUIRE(admin == merovingian::observability::AuditCategory::admin);

                // The name produced by `audit_category_name` must be
                // acceptable to `audit_category_from_name` — i.e. the
                // pair is a true bijection on the known set.
                for (auto const cat : {merovingian::observability::AuditCategory::auth,
                                       merovingian::observability::AuditCategory::key_lifecycle,
                                       merovingian::observability::AuditCategory::policy,
                                       merovingian::observability::AuditCategory::moderation,
                                       merovingian::observability::AuditCategory::admin})
                {
                    auto const name = std::string_view{merovingian::observability::audit_category_name(cat)};
                    REQUIRE(merovingian::observability::audit_category_from_name(name).value() == cat);
                }
            }
        }
    }
}

SCENARIO("audit_category_from_name returns nullopt for unknown names", "[observability][audit]")
{
    GIVEN("a list of typo / unknown category names")
    {
        WHEN("the lookup is called")
        {
            auto const bogus = merovingian::observability::audit_category_from_name("authz");
            auto const empty = merovingian::observability::audit_category_from_name("");
            auto const cased = merovingian::observability::audit_category_from_name("Policy");

            THEN("the lookup returns std::nullopt so the HTTP handler can answer 400")
            {
                REQUIRE(bogus == std::nullopt);
                REQUIRE(empty == std::nullopt);
                REQUIRE(cased == std::nullopt);
            }
        }
    }
}
