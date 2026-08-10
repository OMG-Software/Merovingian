// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::push
{

// Matrix v1.19 CS API §push-notifications defines four condition kinds that
// this evaluator implements: `event_match`, `contains_display_name`,
// `room_member_count`, and `sender_notification_permission`. Any other kind
// (e.g. `event_property_is`, `event_property_contains`) parses to `unknown`
// and — per spec ("Unrecognised conditions MUST NOT match any events") —
// never matches, which effectively disables the rule that references it.
enum class PushConditionKind
{
    event_match,
    contains_display_name,
    room_member_count,
    sender_notification_permission,
    unknown,
};

// One condition of an `override`/`underride` push rule. Field usage depends
// on `kind`:
//   event_match                     -> key, pattern
//   contains_display_name           -> (none)
//   room_member_count               -> is
//   sender_notification_permission  -> key
struct PushCondition final
{
    PushConditionKind kind{PushConditionKind::unknown};
    std::string key{};
    std::string pattern{};
    std::string is{};
};

// The five push rule kinds, checked in this exact precedence order per spec:
// override > content > room > sender > underride.
enum class PushRuleKind
{
    override_kind,
    content,
    room,
    sender,
    underride,
};

// A single parsed push rule. `content_pattern` is populated only for
// `PushRuleKind::content` rules (the rule's own `pattern` field, matched
// against `content.body`); `conditions` is populated only for `override` and
// `underride` rules. `room` and `sender` rules match implicitly via
// `rule_id` (the room ID / sender's user ID respectively) and use neither.
//
// The action outcome is pre-resolved at parse time rather than kept as a raw
// actions array: `notify` is true iff the rule's `actions` array contains the
// `"notify"` string action (the historical `dont_notify`/`coalesce` actions
// are ignored, per spec, exactly as an empty actions array would be).
// `tweak_sound` and `tweak_highlight` mirror the `set_tweak` actions the
// default ruleset and Matrix v1.19 both define.
struct PushRule final
{
    std::string rule_id{};
    PushRuleKind kind{PushRuleKind::override_kind};
    bool enabled{true};
    bool is_default{false};
    std::vector<PushCondition> conditions{};
    std::string content_pattern{};
    bool notify{false};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
};

// A user's full push ruleset, split by kind in spec precedence order.
struct PushRuleset final
{
    std::vector<PushRule> override_rules{};
    std::vector<PushRule> content_rules{};
    std::vector<PushRule> room_rules{};
    std::vector<PushRule> sender_rules{};
    std::vector<PushRule> underride_rules{};
};

// Parses a stored ruleset (the shape produced by
// `client_server.cpp`'s `default_push_ruleset()` and returned by
// `GET /_matrix/client/v3/pushrules/global/`: an object with `content`,
// `override`, `room`, `sender`, and `underride` array members) into the typed
// form above. Malformed rules (missing `rule_id`, wrong-typed fields) are
// skipped rather than failing the whole parse, so one corrupt row cannot take
// down evaluation for the rest of a user's ruleset. Pure; no I/O.
[[nodiscard]] auto parse_push_ruleset(canonicaljson::Object const& ruleset) -> PushRuleset;

// Contextual facts the evaluator needs beyond the event and ruleset, all of
// which the caller must already have computed (room state, member count,
// power levels) before calling evaluate_push_rules — this module never reads
// a database or does I/O.
struct PushEvaluationContext final
{
    std::string receiving_user_id{};
    std::string receiving_user_display_name{};
    std::uint64_t room_member_count{0U};
    std::int64_t sender_power_level{0};
    // Power level required to trigger a notification of a given
    // `sender_notification_permission` key (from the room's
    // m.room.power_levels `content.notifications` map). A key absent here
    // falls back to `default_notification_power_level`.
    std::unordered_map<std::string, std::int64_t> notification_power_levels{};
    std::int64_t default_notification_power_level{50};
};

// Resolved outcome of evaluating one event against one ruleset.
// `matched_rule_id` is empty when no rule matched (the spec's "the
// homeserver MUST NOT notify the Push Gateway for that event" case); in that
// case `notify` is always false.
struct PushEvaluationResult final
{
    bool notify{false};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
    std::string matched_rule_id{};
};

// Evaluates `event` (a full client-event-shaped JSON object: `type`,
// `sender`, `room_id`, `content`, and optionally `state_key`) against
// `ruleset` for the receiving user described by `context`.
//
// Behaviour, per Matrix v1.19 CS API §push-notifications:
//   - Events sent by the receiving user themselves never notify ("Homeservers
//     MUST NOT notify the Push Gateway for events that the user has sent
//     themselves").
//   - `.m.rule.master`, if enabled, always wins regardless of its position in
//     the override list or of any other rule, user-defined or not.
//   - Otherwise rule kinds are checked in precedence order: override >
//     content > room > sender > underride. Within a kind, rules are checked
//     in list order and the first enabled, matching rule wins.
//   - Disabled rules never match. A rule with no conditions always matches.
//   - If no rule matches, the result is "do not notify".
//
// Pure and side-effect-free: no network, no database, no locks. Safe to call
// while the runtime holds its mutex, and safe to call once per event without
// re-parsing the ruleset JSON (parse it once via parse_push_ruleset and reuse
// the typed PushRuleset across every event).
[[nodiscard]] auto evaluate_push_rules(PushRuleset const& ruleset, canonicaljson::Value const& event,
                                       PushEvaluationContext const& context) -> PushEvaluationResult;

} // namespace merovingian::push
