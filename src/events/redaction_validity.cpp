// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/redaction_validity.hpp"

#include "merovingian/events/authorization.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <variant>

namespace merovingian::events
{
namespace
{

    constexpr auto default_redact_level = std::int64_t{50};

    [[nodiscard]] auto object_of(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = member_of(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
    }

} // namespace

auto redaction_target(canonicaljson::Value const& redaction_event, rooms::RoomVersionPolicy const& policy)
    -> std::optional<std::string>
{
    auto const* event = object_of(redaction_event);
    if (event == nullptr)
    {
        return std::nullopt;
    }
    auto const* type = string_of(*event, "type");
    if (type == nullptr || *type != "m.room.redaction")
    {
        return std::nullopt;
    }

    auto const* holder = event;
    if (policy.redaction_rules == rooms::RedactionRules::room_v11_plus)
    {
        auto const* content = member_of(*event, "content");
        holder = content == nullptr ? nullptr : object_of(*content);
    }
    if (holder == nullptr)
    {
        return std::nullopt;
    }
    auto const* target = string_of(*holder, "redacts");
    if (target == nullptr || target->empty())
    {
        return std::nullopt;
    }
    return *target;
}

auto sender_meets_redact_level(canonicaljson::Value const& redaction_event, RedactionContext const& context,
                               rooms::RoomVersionPolicy const& policy) -> bool
{
    auto const* redaction = object_of(redaction_event);
    auto const* sender = redaction == nullptr ? nullptr : string_of(*redaction, "sender");
    if (sender == nullptr)
    {
        return false;
    }
    auto const redact_level = has_content(context.power_levels)
                                  ? extract_power_level_key(context.power_levels, "redact", default_redact_level,
                                                            !policy.power_levels_require_integers)
                                  : default_redact_level;
    return effective_sender_power(context.power_levels, *sender, context.create, policy) >= redact_level;
}

auto judge_redaction(canonicaljson::Value const& redaction_event, canonicaljson::Value const& target_event,
                     RedactionContext const& context, rooms::RoomVersionPolicy const& policy) -> RedactionVerdict
{
    auto const* redaction = object_of(redaction_event);
    auto const* target = object_of(target_event);
    if (redaction == nullptr || target == nullptr)
    {
        return RedactionVerdict::sender_lacks_authority;
    }

    auto const* target_type = string_of(*target, "type");
    if (target_type != nullptr && *target_type == "m.room.create")
    {
        return RedactionVerdict::target_not_redactable;
    }

    auto const* redaction_sender = string_of(*redaction, "sender");
    if (redaction_sender == nullptr)
    {
        return RedactionVerdict::sender_lacks_authority;
    }

    // Condition 1: the sender's power level is at least the redact level.
    if (sender_meets_redact_level(redaction_event, context, policy))
    {
        return RedactionVerdict::applies;
    }

    // Condition 2: the sender's domain is the original sender's domain.
    auto const* target_sender = string_of(*target, "sender");
    if (target_sender != nullptr)
    {
        auto const redaction_domain = domain_of(*redaction_sender);
        if (!redaction_domain.empty() && redaction_domain == domain_of(*target_sender))
        {
            return RedactionVerdict::applies;
        }
    }
    return RedactionVerdict::sender_lacks_authority;
}

} // namespace merovingian::events
