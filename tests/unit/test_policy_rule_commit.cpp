// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C49 (ADR-0687): an administrator's policy rule change, its admin_actions row and its audit_log row commit in one
// transaction. Mirrors ADR-0629's account moderation. Spec: not a protocol requirement; the audit trail is this
// server's own (docs/observability-audit.md).

#include "merovingian/database/PersistentAdminAction.hpp"
#include "merovingian/database/PersistentAuditEvent.hpp"
#include "merovingian/database/PersistentPolicyRule.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto audit_row(std::string const& event_type, std::string const& target) -> db::PersistentAuditEvent
{
    return {"policy", event_type, "@admin:example.org", target, "reason", 0U};
}

[[nodiscard]] auto upsert_audit_rows(db::PersistentStore const& store) -> std::ptrdiff_t
{
    return std::ranges::count_if(store.audit_log, [](db::PersistentAuditEvent const& row) {
        return row.event_type == "trust_safety.policy_rule.upsert";
    });
}

} // namespace

SCENARIO("A policy rule and its two records commit together", "[database][persistence][policy][audit][c49]")
{
    GIVEN("a store")
    {
        auto store = db::PersistentStore{};
        auto const rule =
            db::PersistentPolicyRule{"federation:evil.example", "federation", "evil.example", "deny", "spam"};
        auto const action = db::PersistentAdminAction{"@admin:example.org", "trust_safety.policy_rule.upsert",
                                                      "federation:evil.example"};

        WHEN("the rule is committed")
        {
            auto const committed = db::commit_policy_rule_with_audit(
                store, rule, action, audit_row("trust_safety.policy_rule.upsert", rule.rule_id));

            THEN("the rule, the admin action and the audit row all exist")
            {
                REQUIRE(committed);
                REQUIRE(store.policy_rules.size() == 1U);
                REQUIRE(store.admin_actions.size() == 1U);
                REQUIRE(upsert_audit_rows(store) == 1);
                REQUIRE(store.audit_log.back().created_at_ms != 0U);
            }
        }

        WHEN("the audit write fails")
        {
            db::force_persist_failure_for_statement(store, "policy_rule_audit");
            auto const committed = db::commit_policy_rule_with_audit(
                store, rule, action, audit_row("trust_safety.policy_rule.upsert", rule.rule_id));

            THEN("the rule is not in force and neither record exists")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.policy_rules.empty());
                REQUIRE(store.admin_actions.empty());
                REQUIRE(upsert_audit_rows(store) == 0);
            }
        }

        WHEN("the admin action write fails")
        {
            db::force_persist_failure_for_statement(store, "append_admin_action");
            auto const committed = db::commit_policy_rule_with_audit(
                store, rule, action, audit_row("trust_safety.policy_rule.upsert", rule.rule_id));

            THEN("no audit row is left for a rule that was never stored")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.policy_rules.empty());
                REQUIRE(upsert_audit_rows(store) == 0);
            }
        }

        WHEN("an incomplete rule is committed")
        {
            auto const committed =
                db::commit_policy_rule_with_audit(store, {"", "federation", "evil.example", "deny", ""}, action,
                                                  audit_row("trust_safety.policy_rule.upsert", "x"));

            THEN("nothing is written")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.admin_actions.empty());
                REQUIRE(upsert_audit_rows(store) == 0);
            }
        }
    }
}

SCENARIO("A policy rule removal commits with its two records", "[database][persistence][policy][audit][c49]")
{
    GIVEN("a store holding a rule")
    {
        auto store = db::PersistentStore{};
        REQUIRE(db::store_policy_rule(store, {"media:abc", "media", "abc", "quarantine", "held"}));
        auto const action =
            db::PersistentAdminAction{"@admin:example.org", "trust_safety.policy_rule.delete", "media:abc"};

        WHEN("the removal's audit write fails")
        {
            db::force_persist_failure_for_statement(store, "policy_rule_audit");
            auto const removed = db::commit_policy_rule_removal_with_audit(
                store, "media:abc", action, audit_row("trust_safety.policy_rule.delete", "media:abc"));

            THEN("the rule is still in force")
            {
                REQUIRE_FALSE(removed);
                REQUIRE(store.policy_rules.size() == 1U);
                REQUIRE(store.admin_actions.empty());
            }
        }

        WHEN("the rule is removed, and an unknown one is removed")
        {
            auto const removed = db::commit_policy_rule_removal_with_audit(
                store, "media:abc", action, audit_row("trust_safety.policy_rule.delete", "media:abc"));
            auto const unknown = db::commit_policy_rule_removal_with_audit(
                store, "media:none", action, audit_row("trust_safety.policy_rule.delete", "media:none"));

            THEN("the first removes the rule and records both rows, the second changes nothing")
            {
                REQUIRE(removed);
                REQUIRE_FALSE(unknown);
                REQUIRE(store.policy_rules.empty());
                REQUIRE(store.admin_actions.size() == 1U);
            }
        }
    }
}
