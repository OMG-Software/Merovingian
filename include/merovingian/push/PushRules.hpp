// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/push/PushEvaluationBudget.hpp"
#include "merovingian/push/PushEvaluationContext.hpp"
#include "merovingian/push/PushEvaluationResult.hpp"
#include "merovingian/push/PushRuleset.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::push
{

// Parses a stored ruleset (the shape produced by
// `ClientServerRuntime.cpp`'s `default_push_ruleset()` and returned by
// `GET /_matrix/client/v3/pushrules/global/`: an object with `content`,
// `override`, `room`, `sender`, and `underride` array members) into the typed
// form above. Malformed rules (missing `rule_id`, wrong-typed fields) are
// skipped rather than failing the whole parse, so one corrupt row cannot take
// down evaluation for the rest of a user's ruleset. Pure; no I/O.
[[nodiscard]] auto parse_push_ruleset(canonicaljson::Object const& ruleset) -> PushRuleset;

// The most `content.body` bytes a word-boundary glob searches (ADR-0343). A match must lie within
// them and end at a real word boundary; a keyword further into a longer body is not found.
inline constexpr std::size_t max_push_glob_body_bytes = 4096U;

// The longest value a glob condition on a key other than `content.body` is matched against
// (ADR-0607). The spec matches the entire value, so a longer value cannot be judged on a prefix;
// it does not match a pattern holding a wildcard. A pattern without one compares equal lengths only.
inline constexpr std::size_t max_push_glob_key_value_bytes = 4096U;

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

// evaluate_push_rules(ruleset, event, context), drawing its glob steps from the caller's `budget` instead of a fresh
// one, so many evaluations can share one bound (C15). `glob_steps_used` is what this call spent;
// `glob_budget_exhausted` is whether the budget was spent, by this call or an earlier one. With the budget spent, globs
// do not match.
[[nodiscard]] auto evaluate_push_rules(PushRuleset const& ruleset, canonicaljson::Value const& event,
                                       PushEvaluationContext const& context, PushEvaluationBudget& budget)
    -> PushEvaluationResult;

} // namespace merovingian::push
