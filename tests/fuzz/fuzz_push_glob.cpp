// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the push rule glob matcher through the public evaluator. The bytes before the first
// NUL are a glob pattern (the recipient chooses it); the rest is a message body (the sender
// chooses it). The pattern is used three ways: as a content rule, as an event_match condition on
// content.body, and as an event_match condition on the event type.

#include "fuzz_input.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/push/PushCondition.hpp"
#include "merovingian/push/PushConditionKind.hpp"
#include "merovingian/push/PushEvaluationContext.hpp"
#include "merovingian/push/PushRule.hpp"
#include "merovingian/push/PushRuleKind.hpp"
#include "merovingian/push/PushRuleset.hpp"
#include "merovingian/push/push_rules.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

namespace
{

using merovingian::canonicaljson::make_member;
using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;

[[nodiscard]] auto make_event(std::string body) -> Value
{
    auto content = Object{};
    content.push_back(make_member("body", Value{std::move(body)}));
    auto event = Object{};
    event.push_back(make_member("type", Value{std::string{"m.room.message"}}));
    event.push_back(make_member("sender", Value{std::string{"@a:example.org"}}));
    event.push_back(make_member("room_id", Value{std::string{"!r:example.org"}}));
    event.push_back(make_member("content", Value{std::move(content)}));
    return Value{std::move(event)};
}

[[nodiscard]] auto event_match_rule(std::string rule_id, std::string key, std::string pattern)
    -> merovingian::push::PushRule
{
    auto rule = merovingian::push::PushRule{};
    rule.rule_id = std::move(rule_id);
    rule.kind = merovingian::push::PushRuleKind::override_kind;
    rule.notify = true;
    auto condition = merovingian::push::PushCondition{};
    condition.kind = merovingian::push::PushConditionKind::event_match;
    condition.key = std::move(key);
    condition.pattern = std::move(pattern);
    rule.conditions.push_back(std::move(condition));
    return rule;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    auto const [pattern, body] = merovingian::fuzz::split_at_nul(input);

    auto ruleset = merovingian::push::PushRuleset{};
    auto content_rule = merovingian::push::PushRule{};
    content_rule.rule_id = "content";
    content_rule.kind = merovingian::push::PushRuleKind::content;
    content_rule.content_pattern = std::string{pattern};
    content_rule.notify = true;
    ruleset.content_rules.push_back(std::move(content_rule));
    ruleset.override_rules.push_back(event_match_rule("body", "content.body", std::string{pattern}));
    ruleset.override_rules.push_back(event_match_rule("type", "type", std::string{pattern}));

    auto context = merovingian::push::PushEvaluationContext{};
    context.receiving_user_id = "@b:example.org";
    context.room_member_count = 2U;

    auto const result = merovingian::push::evaluate_push_rules(ruleset, make_event(std::string{body}), context);
    std::ignore = result;
    return 0;
}
