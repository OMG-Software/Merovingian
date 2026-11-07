// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::push
{

// Matrix v1.19 CS API §push-notifications defines six condition kinds, all of
// which this evaluator implements: `event_match`, `contains_display_name`,
// `room_member_count`, `sender_notification_permission`, `event_property_is`,
// and `event_property_contains`. Any other (unrecognised) kind parses to
// `unknown` and — per spec ("Unrecognised conditions MUST NOT match any
// events") — never matches, which effectively disables the rule that
// references it.
enum class PushConditionKind
{
    event_match,
    contains_display_name,
    room_member_count,
    sender_notification_permission,
    event_property_is,
    event_property_contains,
    unknown,
};

} // namespace merovingian::push
