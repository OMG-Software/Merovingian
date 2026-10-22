// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/push/push_rules.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::push
{

// Bounds on one user-defined push rule (R19, ADR-0204). Rules are evaluated
// per local recipient, per event, under runtime.mutex, and again for every
// unread event a /sync counts (R15), so a client must not be able to store a
// rule whose evaluation cost it chooses freely. A rule ID is a room ID, a
// user ID or a client-chosen name; the identifier grammar bounds the first
// two to 255 bytes. The whole rule, in canonical JSON, must fit
// max_push_rule_bytes. How many rules one user may hold is
// `server.client_api.max_push_rules_per_user`.
inline constexpr auto max_push_rule_id_bytes = std::size_t{255U};
inline constexpr auto max_push_rule_pattern_bytes = std::size_t{512U};
inline constexpr auto max_push_rule_conditions = std::size_t{16U};
inline constexpr auto max_push_rule_actions = std::size_t{16U};
inline constexpr auto max_push_rule_bytes = std::size_t{4096U};

// The `{kind}` path parameter: one of override, underride, sender, room,
// content. Anything else is nullopt.
[[nodiscard]] auto parse_push_rule_kind(std::string_view name) noexcept -> std::optional<PushRuleKind>;
[[nodiscard]] auto push_rule_kind_name(PushRuleKind kind) noexcept -> std::string_view;

// The outcome of an edit of a user's push rules: `applied`, or why it was refused and nothing
// changed. (Not std::expected, which this project's toolchain does not build.)
enum class PushRuleEditOutcome : std::uint8_t
{
    applied,
    // No rule of that kind has that ID.
    not_found,
    // A rule ID the spec forbids: empty, longer than max_push_rule_id_bytes,
    // containing '/' or '\', or (room and sender rules) not a room or user ID.
    invalid_rule_id,
    // The body or actions are not a valid rule of the kind, or exceed a bound.
    invalid_rule,
    // The rule ID starts with '.', reserved for server-default rules, which can
    // be enabled, disabled and given new actions but not created or deleted.
    server_default_rule,
    // `before` / `after` names no rule of the same kind.
    unknown_relative_rule,
    // `before` / `after` names a server-default rule.
    relative_to_server_default,
    // Creating the rule would exceed the user's rule cap.
    too_many_rules,
};

// Where PUT places a rule: `before` and `after` are the query parameters of the
// same name. When both are given, `before` decides (spec: "the new or updated
// rule must be the next most important rule with respect to the rule
// identified by before").
struct PushRulePlacement final
{
    std::optional<std::string> before{};
    std::optional<std::string> after{};
};

// One rule of a UserPushRules, as GET returns it. `conditions` is set for
// override and underride rules, `pattern` for content rules.
struct PushRuleEntry final
{
    std::string rule_id{};
    bool is_default{false};
    bool enabled{true};
    canonicaljson::Array actions{};
    std::optional<canonicaljson::Array> conditions{};
    std::optional<std::string> pattern{};
};

// One user's push rules: the server-default ruleset with the user's own rules
// and their changes to the defaults applied, in evaluation order. Spec
// (client-server-api.md, "Predefined Rules"): server-default rules "operate at
// a lower priority than user-defined rules, except for the .m.rule.master rule
// which has always a higher priority than any other rule", so each kind lists
// its user-defined rules first, except that .m.rule.master leads `override`.
//
// The rules are kept as the user's `m.push_rules` account data, whose content
// is `{"global": ruleset()}` (spec, "Push Rules: Events"). Reading it back
// re-applies the stored rules to the current server defaults: a default rule
// the stored copy lacks is added, a stored default rule the server no longer
// has is dropped, and only `enabled` and `actions` of a default rule come from
// the stored copy (ADR-0204). Stored user rules are validated as a PUT would
// be; invalid ones and any beyond the cap are skipped.
//
// Pure: no I/O, no locks.
class UserPushRules final
{
public:
    // `server_defaults` is the default ruleset (homeserver::default_push_ruleset);
    // `stored` is the `global` object of the stored account data, or an empty
    // object when the user has none.
    UserPushRules(canonicaljson::Object const& server_defaults, canonicaljson::Object const& stored,
                  std::size_t max_user_rules);

    // The ruleset object served by GET /pushrules/global/ and stored as the
    // `global` member of `m.push_rules`.
    [[nodiscard]] auto ruleset() const -> canonicaljson::Object;

    // The rule object served by GET /pushrules/global/{kind}/{ruleId}.
    [[nodiscard]] auto rule(PushRuleKind kind, std::string_view rule_id) const -> std::optional<canonicaljson::Object>;

    // PUT /pushrules/global/{kind}/{ruleId}: creates or updates a user-defined
    // rule from the request body. A new rule is enabled; an updated rule keeps
    // its enabled state. Without a placement a new rule becomes the most
    // important user-defined rule of its kind and an updated rule keeps its
    // place. Historical `dont_notify` and `coalesce` actions are stripped.
    [[nodiscard]] auto put_rule(PushRuleKind kind, std::string_view rule_id, canonicaljson::Value const& body,
                                PushRulePlacement const& placement) -> PushRuleEditOutcome;

    // DELETE /pushrules/global/{kind}/{ruleId}. Server-default rules cannot be
    // deleted.
    [[nodiscard]] auto delete_rule(PushRuleKind kind, std::string_view rule_id) -> PushRuleEditOutcome;

    // PUT .../enabled and PUT .../actions, for user-defined and server-default
    // rules alike.
    [[nodiscard]] auto set_enabled(PushRuleKind kind, std::string_view rule_id, bool enabled) -> PushRuleEditOutcome;
    [[nodiscard]] auto set_actions(PushRuleKind kind, std::string_view rule_id, canonicaljson::Value const& actions)
        -> PushRuleEditOutcome;

    // How many user-defined rules the user holds, across all kinds.
    [[nodiscard]] auto user_rule_count() const noexcept -> std::size_t;

private:
    [[nodiscard]] auto rules_of(PushRuleKind kind) noexcept -> std::vector<PushRuleEntry>&;
    [[nodiscard]] auto rules_of(PushRuleKind kind) const noexcept -> std::vector<PushRuleEntry> const&;

    std::array<std::vector<PushRuleEntry>, 5U> kinds_{};
    std::size_t max_user_rules_{0U};
};

} // namespace merovingian::push
