// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/default_push_ruleset.hpp"

#include <string>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto json_str(std::string_view value) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::string{value}};
    }

    [[nodiscard]] auto json_bool(bool value) -> canonicaljson::Value
    {
        return canonicaljson::Value{value};
    }

    [[nodiscard]] auto json_arr(canonicaljson::Array items) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(items)};
    }

    [[nodiscard]] auto json_obj(canonicaljson::Object members) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(members)};
    }

    [[nodiscard]] auto json_member(std::string key, canonicaljson::Value value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::move(key), std::move(value));
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak) -> canonicaljson::Value
    {
        return json_obj({json_member("set_tweak", json_str(tweak))});
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak, std::string_view value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("set_tweak", json_str(tweak)),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak, bool value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("set_tweak", json_str(tweak)),
            json_member("value", json_bool(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_match(std::string_view key, std::string_view pattern)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_match")),
            json_member("pattern", json_str(pattern)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_is(std::string_view key, std::string_view value)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_is")),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_is(std::string_view key, bool value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_is")),
            json_member("value", json_bool(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_contains(std::string_view key, std::string_view value)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_contains")),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_condition_room_member_count(std::string_view member_count) -> canonicaljson::Value
    {
        return json_obj({
            json_member("is", json_str(member_count)),
            json_member("kind", json_str("room_member_count")),
        });
    }

    [[nodiscard]] auto push_condition_sender_notification_permission(std::string_view key) -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("sender_notification_permission")),
        });
    }

    // Spec: CS API v1.19 §m.rule.contains_display_name — condition kind that matches when
    // the event body contains the receiving user's current display name (case-insensitive).
    // No additional fields required beyond "kind".
    [[nodiscard]] auto push_condition_contains_display_name() -> canonicaljson::Value
    {
        return json_obj({
            json_member("kind", json_str("contains_display_name")),
        });
    }

    [[nodiscard]] auto push_rule(std::string_view rule_id, bool enabled, canonicaljson::Array conditions,
                                 canonicaljson::Array actions) -> canonicaljson::Value
    {
        return json_obj({
            json_member("actions", json_arr(std::move(actions))),
            json_member("conditions", json_arr(std::move(conditions))),
            json_member("default", json_bool(true)),
            json_member("enabled", json_bool(enabled)),
            json_member("rule_id", json_str(rule_id)),
        });
    }

} // namespace

auto default_push_ruleset(std::string_view user_id) -> canonicaljson::Object
{
    auto override_rules = canonicaljson::Array{};
    override_rules.push_back(push_rule(".m.rule.master", false, {}, {}));
    override_rules.push_back(push_rule(".m.rule.suppress_notices", true,
                                       canonicaljson::Array{push_condition_event_match("content.msgtype", "m.notice")},
                                       {}));
    override_rules.push_back(push_rule(".m.rule.invite_for_me", true,
                                       canonicaljson::Array{
                                           push_condition_event_match("type", "m.room.member"),
                                           push_condition_event_match("content.membership", "invite"),
                                           push_condition_event_match("state_key", user_id),
                                       },
                                       canonicaljson::Array{
                                           json_str("notify"),
                                           push_action_set_tweak("sound", std::string_view{"default"}),
                                           push_action_set_tweak("highlight", false),
                                       }));
    override_rules.push_back(push_rule(".m.rule.member_event", true,
                                       canonicaljson::Array{push_condition_event_match("type", "m.room.member")}, {}));
    override_rules.push_back(push_rule(
        ".m.rule.is_user_mention", true,
        canonicaljson::Array{push_condition_event_property_contains("content.m\\.mentions.user_ids", user_id)},
        canonicaljson::Array{
            json_str("notify"),
            push_action_set_tweak("sound", std::string_view{"default"}),
            push_action_set_tweak("highlight"),
        }));
    override_rules.push_back(push_rule(".m.rule.is_room_mention", true,
                                       canonicaljson::Array{
                                           push_condition_event_property_is("content.m\\.mentions.room", true),
                                           push_condition_sender_notification_permission("room"),
                                       },
                                       canonicaljson::Array{
                                           json_str("notify"),
                                           push_action_set_tweak("highlight"),
                                       }));
    override_rules.push_back(push_rule(".m.rule.tombstone", true,
                                       canonicaljson::Array{
                                           push_condition_event_match("type", "m.room.tombstone"),
                                           push_condition_event_match("state_key", ""),
                                       },
                                       canonicaljson::Array{
                                           json_str("notify"),
                                           push_action_set_tweak("highlight"),
                                       }));
    override_rules.push_back(push_rule(".m.rule.reaction", true,
                                       canonicaljson::Array{push_condition_event_match("type", "m.reaction")}, {}));
    override_rules.push_back(push_rule(".m.rule.room.server_acl", true,
                                       canonicaljson::Array{
                                           push_condition_event_match("type", "m.room.server_acl"),
                                           push_condition_event_match("state_key", ""),
                                       },
                                       {}));
    override_rules.push_back(push_rule(".m.rule.suppress_edits", true,
                                       canonicaljson::Array{push_condition_event_property_is(
                                           "content.m\\.relates_to.rel_type", std::string_view{"m.replace"})},
                                       {}));
    // Spec: CS API v1.19 §.m.rule.contains_display_name — legacy rule for clients that do
    // not use m.mentions; matches messages whose body contains the user's display name.
    override_rules.push_back(push_rule(".m.rule.contains_display_name", true,
                                       canonicaljson::Array{push_condition_contains_display_name()},
                                       canonicaljson::Array{
                                           json_str("notify"),
                                           push_action_set_tweak("sound", std::string_view{"default"}),
                                           push_action_set_tweak("highlight"),
                                       }));
    // Spec: CS API v1.19 §.m.rule.roomnotif — matches messages containing "@room" when
    // the sender has permission to notify the whole room.
    override_rules.push_back(push_rule(".m.rule.roomnotif", true,
                                       canonicaljson::Array{
                                           push_condition_event_match("content.body", "@room"),
                                           push_condition_sender_notification_permission("room"),
                                       },
                                       canonicaljson::Array{
                                           json_str("notify"),
                                           push_action_set_tweak("highlight"),
                                       }));

    auto underride_rules = canonicaljson::Array{};
    underride_rules.push_back(push_rule(".m.rule.call", true,
                                        canonicaljson::Array{push_condition_event_match("type", "m.call.invite")},
                                        canonicaljson::Array{
                                            json_str("notify"),
                                            push_action_set_tweak("sound", std::string_view{"ring"}),
                                            push_action_set_tweak("highlight", false),
                                        }));
    underride_rules.push_back(push_rule(".m.rule.encrypted_room_one_to_one", true,
                                        canonicaljson::Array{
                                            push_condition_room_member_count("2"),
                                            push_condition_event_match("type", "m.room.encrypted"),
                                        },
                                        canonicaljson::Array{
                                            json_str("notify"),
                                            push_action_set_tweak("sound", std::string_view{"default"}),
                                            push_action_set_tweak("highlight", false),
                                        }));
    underride_rules.push_back(push_rule(".m.rule.room_one_to_one", true,
                                        canonicaljson::Array{
                                            push_condition_room_member_count("2"),
                                            push_condition_event_match("type", "m.room.message"),
                                        },
                                        canonicaljson::Array{
                                            json_str("notify"),
                                            push_action_set_tweak("sound", std::string_view{"default"}),
                                            push_action_set_tweak("highlight", false),
                                        }));
    underride_rules.push_back(push_rule(".m.rule.message", true,
                                        canonicaljson::Array{push_condition_event_match("type", "m.room.message")},
                                        canonicaljson::Array{
                                            json_str("notify"),
                                            push_action_set_tweak("highlight", false),
                                        }));
    underride_rules.push_back(push_rule(".m.rule.encrypted", true,
                                        canonicaljson::Array{push_condition_event_match("type", "m.room.encrypted")},
                                        canonicaljson::Array{
                                            json_str("notify"),
                                            push_action_set_tweak("highlight", false),
                                        }));

    return canonicaljson::Object{
        json_member("content", json_arr({})),
        json_member("override", json_arr(std::move(override_rules))),
        json_member("room", json_arr({})),
        json_member("sender", json_arr({})),
        json_member("underride", json_arr(std::move(underride_rules))),
    };
}

} // namespace merovingian::homeserver
