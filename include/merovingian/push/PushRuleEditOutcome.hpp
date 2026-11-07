// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

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

} // namespace merovingian::push
