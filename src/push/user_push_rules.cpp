// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/user_push_rules.hpp"

#include "merovingian/canonicaljson/serializer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <utility>

namespace merovingian::push
{
namespace
{

    constexpr auto all_kinds = std::to_array<PushRuleKind>({
        PushRuleKind::override_kind,
        PushRuleKind::content,
        PushRuleKind::room,
        PushRuleKind::sender,
        PushRuleKind::underride,
    });

    constexpr auto master_rule_id = std::string_view{".m.rule.master"};

    [[nodiscard]] auto member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        auto const found = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& candidate) {
            return candidate.key == key;
        });
        return found == object.end() ? nullptr : found->value.get();
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto is_server_default_id(std::string_view rule_id) noexcept -> bool
    {
        return !rule_id.empty() && rule_id.front() == '.';
    }

    // Spec (PUT /pushrules/global/{kind}/{ruleId}): "If the string starts with a dot ("."), the
    // request MUST be rejected as this is reserved for server-default rules. Slashes ("/") and
    // backslashes ("\") are also not allowed." Room and sender rules are named by the room ID and
    // user ID they apply to ("Push Rules").
    [[nodiscard]] auto user_rule_id_is_valid(PushRuleKind kind, std::string_view rule_id) noexcept -> bool
    {
        if (rule_id.empty() || rule_id.size() > max_push_rule_id_bytes || is_server_default_id(rule_id) ||
            rule_id.find_first_of("/\\") != std::string_view::npos)
        {
            return false;
        }
        if (kind == PushRuleKind::room)
        {
            return rule_id.front() == '!';
        }
        if (kind == PushRuleKind::sender)
        {
            return rule_id.front() == '@';
        }
        return true;
    }

    [[nodiscard]] auto bounded_string(canonicaljson::Value const* value) noexcept -> std::string const*
    {
        auto const* text = value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
        return text != nullptr && text->size() <= max_push_rule_pattern_bytes ? text : nullptr;
    }

    // `is` of room_member_count: "A decimal integer optionally prefixed by one of, ==, <, >, >=
    // or <=".
    [[nodiscard]] auto member_count_is_valid(std::string_view is) noexcept -> bool
    {
        for (auto const prefix : {std::string_view{"=="}, std::string_view{"<="}, std::string_view{">="},
                                  std::string_view{"<"}, std::string_view{">"}})
        {
            if (is.starts_with(prefix))
            {
                is.remove_prefix(prefix.size());
                break;
            }
        }
        return !is.empty() && is.size() <= 20U && std::ranges::all_of(is, [](char digit) {
            return digit >= '0' && digit <= '9';
        });
    }

    // A condition the spec defines must carry its parameters with their types. A kind the spec
    // does not define is kept as sent: it never matches ("Unrecognised conditions MUST NOT match
    // any events").
    [[nodiscard]] auto condition_is_valid(canonicaljson::Value const& condition) noexcept -> bool
    {
        auto const* object = std::get_if<canonicaljson::Object>(&condition.storage());
        if (object == nullptr)
        {
            return false;
        }
        auto const* kind = bounded_string(member(*object, "kind"));
        if (kind == nullptr)
        {
            return false;
        }
        if (*kind == "event_match")
        {
            return bounded_string(member(*object, "key")) != nullptr &&
                   bounded_string(member(*object, "pattern")) != nullptr;
        }
        if (*kind == "event_property_is" || *kind == "event_property_contains")
        {
            auto const* value = member(*object, "value");
            // "A non-compound canonical JSON value": a string, integer, boolean or null.
            auto const non_compound = value != nullptr && (std::holds_alternative<std::nullptr_t>(value->storage()) ||
                                                           std::holds_alternative<bool>(value->storage()) ||
                                                           std::holds_alternative<std::int64_t>(value->storage()) ||
                                                           bounded_string(value) != nullptr);
            return bounded_string(member(*object, "key")) != nullptr && non_compound;
        }
        if (*kind == "room_member_count")
        {
            auto const* is = bounded_string(member(*object, "is"));
            return is != nullptr && member_count_is_valid(*is);
        }
        if (*kind == "sender_notification_permission")
        {
            return bounded_string(member(*object, "key")) != nullptr;
        }
        return true;
    }

    // The actions to store, or nullopt when `actions` is not a valid actions array. Spec
    // ("Actions"): `notify` and `set_tweak` objects; "Clients and homeservers MUST ignore" the
    // historical `dont_notify` and `coalesce`, "for instance, by stripping them". The `highlight`
    // tweak is a boolean and `sound` a string.
    [[nodiscard]] auto validated_actions(canonicaljson::Value const& actions) -> std::optional<canonicaljson::Array>
    {
        auto const* array = std::get_if<canonicaljson::Array>(&actions.storage());
        if (array == nullptr || array->size() > max_push_rule_actions)
        {
            return std::nullopt;
        }
        auto kept = canonicaljson::Array{};
        for (auto const& action : *array)
        {
            if (auto const* name = std::get_if<std::string>(&action.storage()); name != nullptr)
            {
                if (*name == "notify")
                {
                    kept.push_back(action);
                    continue;
                }
                if (*name == "dont_notify" || *name == "coalesce")
                {
                    continue;
                }
                return std::nullopt;
            }
            auto const* object = std::get_if<canonicaljson::Object>(&action.storage());
            auto const* tweak = object == nullptr ? nullptr : bounded_string(member(*object, "set_tweak"));
            if (tweak == nullptr || tweak->empty())
            {
                return std::nullopt;
            }
            if (auto const* value = member(*object, "value"); value != nullptr)
            {
                if ((*tweak == "highlight" && !std::holds_alternative<bool>(value->storage())) ||
                    (*tweak == "sound" && !std::holds_alternative<std::string>(value->storage())))
                {
                    return std::nullopt;
                }
            }
            kept.push_back(action);
        }
        return kept;
    }

    [[nodiscard]] auto entry_object(PushRuleEntry const& entry) -> canonicaljson::Object
    {
        auto object = canonicaljson::Object{};
        object.push_back(canonicaljson::make_member("actions", canonicaljson::Value{entry.actions}));
        if (entry.conditions.has_value())
        {
            object.push_back(canonicaljson::make_member("conditions", canonicaljson::Value{*entry.conditions}));
        }
        object.push_back(canonicaljson::make_member("default", canonicaljson::Value{entry.is_default}));
        object.push_back(canonicaljson::make_member("enabled", canonicaljson::Value{entry.enabled}));
        if (entry.pattern.has_value())
        {
            object.push_back(canonicaljson::make_member("pattern", canonicaljson::Value{*entry.pattern}));
        }
        object.push_back(canonicaljson::make_member("rule_id", canonicaljson::Value{entry.rule_id}));
        return object;
    }

    // A user-defined rule of `kind` built from a PUT body (or a stored rule, read the same way),
    // or nullopt when the body is not a valid rule or its canonical JSON exceeds
    // max_push_rule_bytes. Conditions apply only to override and underride rules and the pattern
    // only to content rules; a member the kind does not use is ignored.
    [[nodiscard]] auto user_rule_from(PushRuleKind kind, std::string_view rule_id, canonicaljson::Value const& body)
        -> std::optional<PushRuleEntry>
    {
        auto const* object = std::get_if<canonicaljson::Object>(&body.storage());
        auto const* actions_value = object == nullptr ? nullptr : member(*object, "actions");
        if (actions_value == nullptr)
        {
            return std::nullopt;
        }
        auto actions = validated_actions(*actions_value);
        if (!actions.has_value())
        {
            return std::nullopt;
        }
        auto entry = PushRuleEntry{std::string{rule_id}, false, true, std::move(*actions), std::nullopt, std::nullopt};
        if (kind == PushRuleKind::override_kind || kind == PushRuleKind::underride)
        {
            entry.conditions = canonicaljson::Array{};
            if (auto const* conditions_value = member(*object, "conditions"); conditions_value != nullptr)
            {
                auto const* conditions = std::get_if<canonicaljson::Array>(&conditions_value->storage());
                if (conditions == nullptr || conditions->size() > max_push_rule_conditions ||
                    !std::ranges::all_of(*conditions, condition_is_valid))
                {
                    return std::nullopt;
                }
                entry.conditions = *conditions;
            }
        }
        if (kind == PushRuleKind::content)
        {
            // "Content rules take one parameter: pattern".
            auto const* pattern = bounded_string(member(*object, "pattern"));
            if (pattern == nullptr || pattern->empty())
            {
                return std::nullopt;
            }
            entry.pattern = *pattern;
        }
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{entry_object(entry)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none ||
            serialized.output.size() > max_push_rule_bytes)
        {
            return std::nullopt;
        }
        return entry;
    }

    [[nodiscard]] auto default_rule_from(canonicaljson::Object const& object) -> std::optional<PushRuleEntry>
    {
        auto const* rule_id = string_member(object, "rule_id");
        auto const* actions_value = member(object, "actions");
        auto const* actions =
            actions_value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&actions_value->storage());
        if (rule_id == nullptr || actions == nullptr)
        {
            return std::nullopt;
        }
        auto entry = PushRuleEntry{*rule_id, true, true, *actions, std::nullopt, std::nullopt};
        if (auto const* enabled = member(object, "enabled"); enabled != nullptr)
        {
            if (auto const* flag = std::get_if<bool>(&enabled->storage()); flag != nullptr)
            {
                entry.enabled = *flag;
            }
        }
        if (auto const* conditions = member(object, "conditions"); conditions != nullptr)
        {
            if (auto const* array = std::get_if<canonicaljson::Array>(&conditions->storage()); array != nullptr)
            {
                entry.conditions = *array;
            }
        }
        if (auto const* pattern = string_member(object, "pattern"); pattern != nullptr)
        {
            entry.pattern = *pattern;
        }
        return entry;
    }

    [[nodiscard]] auto rule_array(canonicaljson::Object const& ruleset, PushRuleKind kind) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = member(ruleset, push_rule_kind_name(kind));
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
    }

    [[nodiscard]] auto find_rule(std::vector<PushRuleEntry>& rules, std::string_view rule_id) noexcept
        -> std::vector<PushRuleEntry>::iterator
    {
        return std::ranges::find_if(rules, [rule_id](PushRuleEntry const& rule) {
            return rule.rule_id == rule_id;
        });
    }

    // Where the most important user-defined rule of a kind goes: first, except after
    // .m.rule.master, which leads every other rule.
    [[nodiscard]] auto first_user_slot(std::vector<PushRuleEntry> const& rules) noexcept -> std::ptrdiff_t
    {
        auto const found = std::ranges::find_if(rules, [](PushRuleEntry const& rule) {
            return !(rule.is_default && rule.rule_id == master_rule_id);
        });
        return std::distance(rules.begin(), found);
    }

} // namespace

auto parse_push_rule_kind(std::string_view name) noexcept -> std::optional<PushRuleKind>
{
    for (auto const kind : all_kinds)
    {
        if (push_rule_kind_name(kind) == name)
        {
            return kind;
        }
    }
    return std::nullopt;
}

auto push_rule_kind_name(PushRuleKind kind) noexcept -> std::string_view
{
    switch (kind)
    {
    case PushRuleKind::override_kind:
        return "override";
    case PushRuleKind::content:
        return "content";
    case PushRuleKind::room:
        return "room";
    case PushRuleKind::sender:
        return "sender";
    case PushRuleKind::underride:
        return "underride";
    }
    return "override";
}

UserPushRules::UserPushRules(canonicaljson::Object const& server_defaults, canonicaljson::Object const& stored,
                             std::size_t max_user_rules)
    : max_user_rules_{max_user_rules}
{
    auto user_rules = std::size_t{0U};
    for (auto const kind : all_kinds)
    {
        auto defaults = std::vector<PushRuleEntry>{};
        if (auto const* array = rule_array(server_defaults, kind); array != nullptr)
        {
            for (auto const& value : *array)
            {
                auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
                if (auto entry = object == nullptr ? std::nullopt : default_rule_from(*object); entry.has_value())
                {
                    defaults.push_back(std::move(*entry));
                }
            }
        }

        auto users = std::vector<PushRuleEntry>{};
        if (auto const* array = rule_array(stored, kind); array != nullptr)
        {
            for (auto const& value : *array)
            {
                auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
                auto const* rule_id = object == nullptr ? nullptr : string_member(*object, "rule_id");
                if (rule_id == nullptr)
                {
                    continue;
                }
                auto const* enabled_value = member(*object, "enabled");
                auto const* enabled = enabled_value == nullptr ? nullptr : std::get_if<bool>(&enabled_value->storage());
                if (is_server_default_id(*rule_id))
                {
                    // Only the user's changes to a default rule the server still has.
                    auto const target = find_rule(defaults, *rule_id);
                    if (target == defaults.end())
                    {
                        continue;
                    }
                    if (enabled != nullptr)
                    {
                        target->enabled = *enabled;
                    }
                    if (auto const* actions_value = member(*object, "actions"); actions_value != nullptr)
                    {
                        if (auto actions = validated_actions(*actions_value); actions.has_value())
                        {
                            target->actions = std::move(*actions);
                        }
                    }
                    continue;
                }
                if (user_rules >= max_user_rules_ || !user_rule_id_is_valid(kind, *rule_id) ||
                    find_rule(users, *rule_id) != users.end())
                {
                    continue;
                }
                if (auto entry = user_rule_from(kind, *rule_id, value); entry.has_value())
                {
                    entry->enabled = enabled == nullptr || *enabled;
                    users.push_back(std::move(*entry));
                    ++user_rules;
                }
            }
        }

        auto& merged = rules_of(kind);
        auto const master = find_rule(defaults, master_rule_id);
        if (master != defaults.end())
        {
            merged.push_back(std::move(*master));
            defaults.erase(master);
        }
        std::ranges::move(users, std::back_inserter(merged));
        std::ranges::move(defaults, std::back_inserter(merged));
    }
}

auto UserPushRules::ruleset() const -> canonicaljson::Object
{
    auto ruleset = canonicaljson::Object{};
    for (auto const kind : {PushRuleKind::content, PushRuleKind::override_kind, PushRuleKind::room,
                            PushRuleKind::sender, PushRuleKind::underride})
    {
        auto array = canonicaljson::Array{};
        for (auto const& entry : rules_of(kind))
        {
            array.emplace_back(entry_object(entry));
        }
        ruleset.push_back(
            canonicaljson::make_member(std::string{push_rule_kind_name(kind)}, canonicaljson::Value{std::move(array)}));
    }
    return ruleset;
}

auto UserPushRules::rule(PushRuleKind kind, std::string_view rule_id) const -> std::optional<canonicaljson::Object>
{
    auto const& rules = rules_of(kind);
    auto const found = std::ranges::find_if(rules, [rule_id](PushRuleEntry const& entry) {
        return entry.rule_id == rule_id;
    });
    if (found == rules.end())
    {
        return std::nullopt;
    }
    return entry_object(*found);
}

auto UserPushRules::put_rule(PushRuleKind kind, std::string_view rule_id, canonicaljson::Value const& body,
                             PushRulePlacement const& placement) -> PushRuleEditOutcome
{
    if (is_server_default_id(rule_id))
    {
        return PushRuleEditOutcome::server_default_rule;
    }
    if (!user_rule_id_is_valid(kind, rule_id))
    {
        return PushRuleEditOutcome::invalid_rule_id;
    }
    auto entry = user_rule_from(kind, rule_id, body);
    if (!entry.has_value())
    {
        return PushRuleEditOutcome::invalid_rule;
    }

    auto& rules = rules_of(kind);
    auto const relative_id = placement.before.has_value() ? placement.before : placement.after;
    if (relative_id.has_value() && *relative_id != rule_id)
    {
        auto const relative = find_rule(rules, *relative_id);
        if (relative == rules.end())
        {
            return PushRuleEditOutcome::unknown_relative_rule;
        }
        if (relative->is_default)
        {
            return PushRuleEditOutcome::relative_to_server_default;
        }
    }

    auto existing = find_rule(rules, rule_id);
    if (existing == rules.end() && user_rule_count() >= max_user_rules_)
    {
        return PushRuleEditOutcome::too_many_rules;
    }
    if (existing != rules.end())
    {
        entry->enabled = existing->enabled;
        if (!relative_id.has_value() || *relative_id == rule_id)
        {
            *existing = std::move(*entry);
            return PushRuleEditOutcome::applied;
        }
        rules.erase(existing);
    }

    auto position = first_user_slot(rules);
    if (relative_id.has_value() && *relative_id != rule_id)
    {
        position = std::distance(rules.begin(), find_rule(rules, *relative_id));
        if (!placement.before.has_value())
        {
            ++position;
        }
    }
    rules.insert(rules.begin() + position, std::move(*entry));
    return PushRuleEditOutcome::applied;
}

auto UserPushRules::delete_rule(PushRuleKind kind, std::string_view rule_id) -> PushRuleEditOutcome
{
    auto& rules = rules_of(kind);
    auto const found = find_rule(rules, rule_id);
    if (found == rules.end())
    {
        return PushRuleEditOutcome::not_found;
    }
    if (found->is_default)
    {
        return PushRuleEditOutcome::server_default_rule;
    }
    rules.erase(found);
    return PushRuleEditOutcome::applied;
}

auto UserPushRules::set_enabled(PushRuleKind kind, std::string_view rule_id, bool enabled) -> PushRuleEditOutcome
{
    auto& rules = rules_of(kind);
    auto const found = find_rule(rules, rule_id);
    if (found == rules.end())
    {
        return PushRuleEditOutcome::not_found;
    }
    found->enabled = enabled;
    return PushRuleEditOutcome::applied;
}

auto UserPushRules::set_actions(PushRuleKind kind, std::string_view rule_id, canonicaljson::Value const& actions)
    -> PushRuleEditOutcome
{
    auto& rules = rules_of(kind);
    auto const found = find_rule(rules, rule_id);
    if (found == rules.end())
    {
        return PushRuleEditOutcome::not_found;
    }
    auto validated = validated_actions(actions);
    if (!validated.has_value())
    {
        return PushRuleEditOutcome::invalid_rule;
    }
    found->actions = std::move(*validated);
    return PushRuleEditOutcome::applied;
}

auto UserPushRules::user_rule_count() const noexcept -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& rules : kinds_)
    {
        count += static_cast<std::size_t>(std::ranges::count_if(rules, [](PushRuleEntry const& entry) {
            return !entry.is_default;
        }));
    }
    return count;
}

auto UserPushRules::rules_of(PushRuleKind kind) noexcept -> std::vector<PushRuleEntry>&
{
    return kinds_.at(static_cast<std::size_t>(kind));
}

auto UserPushRules::rules_of(PushRuleKind kind) const noexcept -> std::vector<PushRuleEntry> const&
{
    return kinds_.at(static_cast<std::size_t>(kind));
}

} // namespace merovingian::push
