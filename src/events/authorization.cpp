// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/authorization.hpp"

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::events
{
namespace
{

    [[nodiscard]] auto auth_rule_name(rooms::AuthRules rules) noexcept -> char const*
    {
        switch (rules)
        {
        case rooms::AuthRules::room_v1:
            return "room_v1";
        case rooms::AuthRules::room_v6_plus:
            return "room_v6_plus";
        case rooms::AuthRules::room_v12:
            // Distinct hook for auditability: v12 adds creator privilege (MSC4289)
            // and implicit create (MSC4291) on top of the v6+ rule base.
            return "room_v12";
        }

        return "unknown";
    }

    [[nodiscard]] auto requires_power_levels(std::string_view event_type) noexcept -> bool
    {
        return event_type != "m.room.create";
    }

    [[nodiscard]] auto requires_membership(std::string_view event_type) noexcept -> bool
    {
        return event_type == "m.room.member";
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object,
                                     std::string_view key) noexcept -> canonicaljson::Value const*
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object,
                                     std::string_view key) noexcept -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object,
                                      std::string_view key) noexcept -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object,
                                               std::string_view key) noexcept -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto value_is_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto value_has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
    }

    [[nodiscard]] auto make_denied(std::string step, std::string reason) -> EventAuthorizationDecision
    {
        LOG_DEBUG(observability::diagnostic_log_summary("event_auth", "authorization.rejected",
                                                        {
                                                            {"rule_step", step,   false},
                                                            {"reason",    reason, false}
        }));
        return {false, {}, std::move(step), std::move(reason)};
    }

    [[nodiscard]] auto make_allowed(std::string step) -> EventAuthorizationDecision
    {
        return {true, {}, std::move(step), {}};
    }

    [[nodiscard]] auto event_content_string(canonicaljson::Value const& event,
                                            std::string_view key) noexcept -> std::string const*
    {
        auto const* obj = value_is_object(event);
        if (obj == nullptr)
        {
            return nullptr;
        }
        auto const* content = object_member_as_object(*obj, "content");
        return content == nullptr ? nullptr : string_member(*content, key);
    }

    [[nodiscard]] auto extract_user_level_from_users(canonicaljson::Object const& users_object,
                                                     std::string_view user_id) noexcept -> std::int64_t
    {
        if (auto const* level = integer_member(users_object, user_id); level != nullptr)
        {
            return *level;
        }
        return -1;
    }

    [[nodiscard]] auto membership_at_least_one_of(MembershipState current,
                                                  std::initializer_list<MembershipState> required) noexcept -> bool
    {
        for (auto const m : required)
        {
            if (current == m)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto user_can_redact(std::int64_t sender_power, std::int64_t redact_level,
                                       std::int64_t ban_level) noexcept -> bool
    {
        return sender_power >= redact_level || sender_power >= ban_level;
    }

    [[nodiscard]] auto array_contains_string(canonicaljson::Value const& value,
                                             std::string_view needle) noexcept -> bool
    {
        auto const* array = std::get_if<canonicaljson::Array>(&value.storage());
        if (array == nullptr)
        {
            return false;
        }
        return std::ranges::any_of(*array, [needle](canonicaljson::Value const& element) {
            auto const* text = std::get_if<std::string>(&element.storage());
            return text != nullptr && *text == needle;
        });
    }

    // MSC4289 (room v12): the create event's sender and every user listed in the
    // create event's content.additional_creators are room creators. Only room
    // versions whose policy privileges creators treat them specially.
    [[nodiscard]] auto user_is_room_creator(canonicaljson::Value const& create_event, std::string_view user_id,
                                            rooms::RoomVersionPolicy const& policy) noexcept -> bool
    {
        if (!policy.privilege_room_creators)
        {
            return false;
        }
        auto const* obj = value_is_object(create_event);
        if (obj == nullptr)
        {
            return false;
        }
        if (auto const* sender = string_member(*obj, "sender"); sender != nullptr && *sender == user_id)
        {
            return true;
        }
        auto const* content = object_member_as_object(*obj, "content");
        if (content == nullptr)
        {
            return false;
        }
        auto const* additional = object_member(*content, "additional_creators");
        return additional != nullptr && array_contains_string(*additional, user_id);
    }

    // The "creator infinite power" sentinel for MSC4289. A room creator outranks
    // every integer power level, so comparisons treat their power as the maximum
    // representable value rather than a literal number from the power_levels event.
    constexpr auto creator_power = std::numeric_limits<std::int64_t>::max();

    [[nodiscard]] auto effective_sender_power(canonicaljson::Value const& power_levels, std::string_view sender,
                                              canonicaljson::Value const& create_event,
                                              rooms::RoomVersionPolicy const& policy) noexcept -> std::int64_t
    {
        // MSC4289: room creators hold an effectively infinite power level that is
        // independent of (and overrides) any entry in the power_levels event.
        if (user_is_room_creator(create_event, sender, policy))
        {
            return creator_power;
        }
        if (value_has_content(power_levels))
        {
            return extract_user_power_level(power_levels, sender);
        }
        auto const* creator = event_content_string(create_event, "creator");
        if (creator != nullptr && sender == *creator)
        {
            return 100;
        }
        return 0;
    }

} // namespace

auto auth_rule_hook_name(rooms::RoomVersionPolicy const& policy) -> std::string
{
    return std::string{"auth_rules."} + auth_rule_name(policy.auth_rules);
}

auto membership_name(MembershipState membership) noexcept -> char const*
{
    switch (membership)
    {
    case MembershipState::leave:
        return "leave";
    case MembershipState::invite:
        return "invite";
    case MembershipState::join:
        return "join";
    case MembershipState::ban:
        return "ban";
    case MembershipState::knock:
        return "knock";
    case MembershipState::restricted:
        return "restricted";
    }

    return "unknown";
}

auto power_level_allows(PowerLevelPolicy policy) noexcept -> bool
{
    return policy.sender_power >= policy.required_power;
}

auto membership_policy_allows(MembershipPolicy policy) -> EventAuthorizationDecision
{
    if (policy.target_is_restricted)
    {
        return {false, "membership", "4", "target membership is restricted"};
    }
    if (policy.requested_membership == MembershipState::join && policy.target_is_sender)
    {
        return {true, "membership", "4", {}};
    }
    if (policy.requested_membership == MembershipState::invite)
    {
        if (policy.sender_power >= policy.invite_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to invite"};
    }
    if (policy.requested_membership == MembershipState::restricted)
    {
        if (policy.sender_power >= policy.restrict_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to restrict membership"};
    }
    if (policy.requested_membership == MembershipState::leave)
    {
        if (policy.target_is_sender)
        {
            return {true, "membership", "4", {}};
        }
        if (policy.sender_power >= policy.remove_power)
        {
            return {true, "membership", "4", {}};
        }
        return {false, "membership", "4", "insufficient power to remove another member"};
    }

    return {false, "membership", "4", "membership transition is not allowed"};
}

auto parse_membership_state(std::string_view membership) noexcept -> MembershipState
{
    if (membership == "join")
    {
        return MembershipState::join;
    }
    if (membership == "invite")
    {
        return MembershipState::invite;
    }
    if (membership == "leave")
    {
        return MembershipState::leave;
    }
    if (membership == "ban")
    {
        return MembershipState::ban;
    }
    if (membership == "knock")
    {
        return MembershipState::knock;
    }
    return MembershipState::leave;
}

auto domain_of(std::string_view matrix_id) noexcept -> std::string_view
{
    auto const colon = matrix_id.find(':');
    if (colon == std::string_view::npos)
    {
        return {};
    }
    return matrix_id.substr(colon + 1);
}

auto extract_content_membership(canonicaljson::Value const& event) noexcept -> std::string
{
    auto const* membership = event_content_string(event, "membership");
    return membership == nullptr ? std::string{} : *membership;
}

auto extract_user_power_level(canonicaljson::Value const& power_levels_event,
                              std::string_view user_id) noexcept -> std::int64_t
{
    auto const* obj = value_is_object(power_levels_event);
    if (obj == nullptr)
    {
        return 0;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return 0;
    }
    auto const default_level = extract_power_level_key(power_levels_event, "users_default", 0);
    auto const* users = object_member_as_object(*content, "users");
    if (users == nullptr)
    {
        return default_level;
    }
    auto const user_level = extract_user_level_from_users(*users, user_id);
    return user_level >= 0 ? user_level : default_level;
}

auto extract_power_level_key(canonicaljson::Value const& power_levels_event, std::string_view key,
                             std::int64_t default_value) noexcept -> std::int64_t
{
    auto const* obj = value_is_object(power_levels_event);
    if (obj == nullptr)
    {
        return default_value;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return default_value;
    }
    if (auto const* level = integer_member(*content, key); level != nullptr)
    {
        return *level;
    }
    if (auto const* events = object_member_as_object(*content, "events"); events != nullptr)
    {
        if (auto const* level = integer_member(*events, key); level != nullptr)
        {
            return *level;
        }
    }
    return default_value;
}

auto authorize_event(rooms::RoomVersionPolicy const& policy,
                     EventAuthorizationRequest const& request) -> EventAuthorizationDecision
{
    auto const rule_hook = auth_rule_hook_name(policy);
    if (policy.id != request.room_version)
    {
        return {false, rule_hook, "0", "room version mismatch"};
    }
    if (request.event_type.empty())
    {
        return {false, rule_hook, "0", "event type is required"};
    }
    if (!power_level_allows(request.power_level))
    {
        return {false, rule_hook, "0", "insufficient power level"};
    }
    if (requires_membership(request.event_type))
    {
        auto membership_decision = membership_policy_allows(request.membership);
        membership_decision.rule_hook = rule_hook;
        return membership_decision;
    }

    return {true, rule_hook, "0", {}};
}

auto authorize_event_against_auth_events(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                                         AuthEventMap const& auth_events) -> EventAuthorizationDecision
{
    auto const* obj = value_is_object(event);
    if (obj == nullptr)
    {
        return make_denied("0", "event must be an object");
    }

    auto const* event_type = string_member(*obj, "type");
    if (event_type == nullptr || event_type->empty())
    {
        return make_denied("0", "missing event type");
    }
    auto const* sender = string_member(*obj, "sender");
    if (sender == nullptr || sender->empty())
    {
        return make_denied("0", "missing sender");
    }

    // Step 1: m.room.create allows if this is the first event (no create event in auth events)
    if (*event_type == "m.room.create")
    {
        if (!value_has_content(auth_events.create))
        {
            return make_allowed("1");
        }
        return make_denied("1", "room already has a create event");
    }

    // Step 2: All other events require a create event
    if (!value_has_content(auth_events.create))
    {
        return make_denied("2", "room has no create event");
    }

    // Step 3: For v6+ and v12, only reject cross-domain senders when the room
    // explicitly disables federation via content.m.federate = false. When m.federate
    // is absent or true the check does not apply and cross-domain senders are permitted.
    // Spec: Matrix Server-Server API v1.18 — Authorization Rules, Step 3.
    // URL: https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
    if (policy.auth_rules == rooms::AuthRules::room_v6_plus ||
        policy.auth_rules == rooms::AuthRules::room_v12)
    {
        auto const* create_obj = value_is_object(auth_events.create);
        auto is_non_federated = false;
        if (create_obj != nullptr)
        {
            auto const* content = object_member_as_object(*create_obj, "content");
            if (content != nullptr)
            {
                auto const* federate_val = object_member(*content, "m.federate");
                if (federate_val != nullptr)
                {
                    auto const* federate_bool = std::get_if<bool>(&federate_val->storage());
                    is_non_federated = (federate_bool != nullptr && !*federate_bool);
                }
            }
        }

        if (is_non_federated)
        {
            auto const sender_domain = domain_of(*sender);
            // v6–v10 rooms store the creator in content.creator; v11+ rooms (including v12)
            // removed content.creator — use the create event's sender field as the fallback.
            auto const* content_creator = event_content_string(auth_events.create, "creator");
            std::string_view creator_domain_src;
            if (content_creator != nullptr)
            {
                creator_domain_src = *content_creator;
            }
            else if (create_obj != nullptr)
            {
                auto const* create_sender = string_member(*create_obj, "sender");
                if (create_sender != nullptr)
                {
                    creator_domain_src = *create_sender;
                }
            }
            if (creator_domain_src.empty())
            {
                return make_denied("3", "create event has no identifiable creator");
            }
            if (sender_domain != domain_of(creator_domain_src))
            {
                return make_denied("3", "sender domain does not match creator domain");
            }
        }
    }

    // Steps 4-9: m.room.member events
    if (*event_type == "m.room.member")
    {
        auto const* state_key = string_member(*obj, "state_key");
        if (state_key == nullptr || state_key->empty())
        {
            return make_denied("4", "m.room.member requires a state_key");
        }

        auto const content_membership = extract_content_membership(event);
        auto const requested = parse_membership_state(content_membership);

        auto const target_is_sender = *sender == *state_key;

        auto sender_current_membership = MembershipState::leave;
        if (value_has_content(auth_events.sender_member))
        {
            sender_current_membership = parse_membership_state(extract_content_membership(auth_events.sender_member));
        }

        auto target_current_membership = MembershipState::leave;
        if (target_is_sender && value_has_content(auth_events.sender_member))
        {
            target_current_membership = parse_membership_state(extract_content_membership(auth_events.sender_member));
        }
        else if (value_has_content(auth_events.target_member))
        {
            target_current_membership = parse_membership_state(extract_content_membership(auth_events.target_member));
        }

        // Step 5: For join, sender must equal state_key (v6+)
        if (requested == MembershipState::join && !target_is_sender)
        {
            return make_denied("5", "cannot force another user to join");
        }

        // Step 5 continued: A user can join if they are joined already (re-join accepted)
        if (requested == MembershipState::join && target_is_sender)
        {
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("5", "banned user cannot join");
            }

            // Matrix auth rule: the room creator's initial join is allowed when
            // the only prior state is m.room.create — i.e. they have no existing
            // membership event yet. This bootstraps every room before join rules
            // or power levels exist.
            if (!value_has_content(auth_events.sender_member) && !value_has_content(auth_events.target_member))
            {
                auto const* creator = event_content_string(auth_events.create, "creator");
                if (creator != nullptr && *creator == *sender)
                {
                    return make_allowed("5");
                }
            }

            // Check join rules
            auto join_rule = std::string{"invite"};
            if (value_has_content(auth_events.join_rules))
            {
                auto const* rule = event_content_string(auth_events.join_rules, "join_rule");
                if (rule != nullptr)
                {
                    join_rule = *rule;
                }
            }

            if (join_rule == "public")
            {
                return make_allowed("5");
            }

            // invite join rule: user must be invited or already joined
            if (join_rule == "invite")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                return make_denied("5", "user was not invited to this invite-only room");
            }

            // knock join rule: knocked users can join if invited
            if (join_rule == "knock")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                return make_denied("5", "user was not invited to knock-restricted room");
            }

            // restricted / restricted_v2 join rules
            if (join_rule == "restricted" || join_rule == "restricted_v2")
            {
                if (membership_at_least_one_of(target_current_membership,
                                               {MembershipState::invite, MembershipState::join}))
                {
                    return make_allowed("5");
                }
                auto const* authorising_user = event_content_string(event, "join_authorised_via_users_server");
                if (authorising_user == nullptr || authorising_user->empty())
                {
                    return make_denied("5", "restricted join requires join_authorised_via_users_server");
                }
                auto const* authorising_member_obj = value_is_object(auth_events.authorising_user_member);
                if (authorising_member_obj == nullptr)
                {
                    return make_denied("5", "restricted join missing authorising user membership");
                }
                auto const* authorising_state_key = string_member(*authorising_member_obj, "state_key");
                if (authorising_state_key == nullptr || *authorising_state_key != *authorising_user)
                {
                    return make_denied("5", "restricted join authorising user does not match membership event");
                }
                if (parse_membership_state(extract_content_membership(auth_events.authorising_user_member)) !=
                    MembershipState::join)
                {
                    return make_denied("5", "restricted join authorising user is not joined");
                }
                auto const invite_power = value_has_content(auth_events.power_levels)
                                              ? extract_power_level_key(auth_events.power_levels, "invite", 0)
                                              : 0;
                auto const authorising_power =
                    effective_sender_power(auth_events.power_levels, *authorising_user, auth_events.create, policy);
                if (authorising_power < invite_power)
                {
                    return make_denied("5", "restricted join authorising user lacks invite power");
                }
                return make_allowed("5");
            }

            return make_denied("5", "unknown join rule");
        }

        // Step 5: knock membership — Spec § Authorization Rules, rule 5.
        // https://spec.matrix.org/v1.18/server-server-api/#authorization-rules
        // A knock event is only valid when:
        //   • sender == state_key (cannot knock for someone else)
        //   • sender is not banned
        //   • sender is not already joined or invited
        //   • the room join_rule is "knock" or "knock_restricted"
        if (requested == MembershipState::knock)
        {
            if (!target_is_sender)
            {
                return make_denied("5", "cannot knock on behalf of another user");
            }
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("5", "banned user cannot knock");
            }
            if (membership_at_least_one_of(target_current_membership,
                                           {MembershipState::join, MembershipState::invite}))
            {
                return make_denied("5", "already joined or invited user cannot knock");
            }

            auto knock_join_rule = std::string{"invite"};
            if (value_has_content(auth_events.join_rules))
            {
                auto const* rule = event_content_string(auth_events.join_rules, "join_rule");
                if (rule != nullptr)
                {
                    knock_join_rule = *rule;
                }
            }
            if (knock_join_rule == "knock" || knock_join_rule == "knock_restricted")
            {
                return make_allowed("5");
            }
            return make_denied("5", "join_rule does not permit knocking");
        }

        // Step 6: invites
        if (requested == MembershipState::invite)
        {
            // Target must not be currently joined or banned
            if (target_current_membership == MembershipState::join)
            {
                return make_denied("6", "cannot invite already-joined user");
            }
            if (target_current_membership == MembershipState::ban)
            {
                return make_denied("6", "cannot invite banned user");
            }

            // Sender must be joined
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("6", "inviter must be joined");
            }

            // Check invite power level
            auto const invite_power = value_has_content(auth_events.power_levels)
                                          ? extract_power_level_key(auth_events.power_levels, "invite", 0)
                                          : 0;
            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
            if (sender_power < invite_power)
            {
                return make_denied("6", "insufficient power to invite");
            }

            return make_allowed("6");
        }

        // Step 7: leave
        if (requested == MembershipState::leave)
        {
            if (target_is_sender)
            {
                // Self-leave is always allowed (unless banned in some room versions)
                return make_allowed("7");
            }

            // Kicking another user
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("7", "kicker must be joined");
            }

            // If target is banned, only someone with ban power can unban
            if (target_current_membership == MembershipState::ban)
            {
                auto const ban_power = value_has_content(auth_events.power_levels)
                                           ? extract_power_level_key(auth_events.power_levels, "ban", 50)
                                           : 50;
                auto const sender_power =
                    effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
                if (sender_power < ban_power)
                {
                    return make_denied("7", "insufficient power to unban");
                }
                return make_allowed("7");
            }

            // Kick requires kick power
            auto const kick_power = value_has_content(auth_events.power_levels)
                                        ? extract_power_level_key(auth_events.power_levels, "kick", 50)
                                        : 50;
            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
            if (sender_power < kick_power)
            {
                return make_denied("7", "insufficient power to kick");
            }

            return make_allowed("7");
        }

        // Step 8: ban
        if (requested == MembershipState::ban)
        {
            if (sender_current_membership != MembershipState::join)
            {
                return make_denied("8", "banner must be joined");
            }

            auto const ban_power = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "ban", 50)
                                       : 50;
            auto const sender_power =
                effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);
            if (sender_power < ban_power)
            {
                return make_denied("8", "insufficient power to ban");
            }

            return make_allowed("8");
        }

        // Unknown membership
        return make_denied("4", "unsupported membership type");
    }

    // Step 10: sender must be in the room (joined)
    auto sender_membership = MembershipState::leave;
    if (value_has_content(auth_events.sender_member))
    {
        sender_membership = parse_membership_state(extract_content_membership(auth_events.sender_member));
    }
    else
    {
        auto const* creator = event_content_string(auth_events.create, "creator");
        if (creator != nullptr && *sender == *creator)
        {
            sender_membership = MembershipState::join;
        }
    }
    if (sender_membership != MembershipState::join)
    {
        return make_denied("10", "sender is not joined to the room");
    }

    // Step 11: check power levels for the event type
    auto const sender_power = effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);

    auto const* state_key = string_member(*obj, "state_key");
    auto const is_state_event = state_key != nullptr;

    if (*event_type == "m.room.power_levels")
    {
        auto const pl_sender_power =
            effective_sender_power(auth_events.power_levels, *sender, auth_events.create, policy);

        auto const* content_obj = object_member_as_object(*obj, "content");
        auto const* new_users = content_obj == nullptr ? nullptr : object_member_as_object(*content_obj, "users");

        // v12/MSC4289: a room creator's power is effectively infinite and cannot be
        // expressed as an integer in content.users. Any m.room.power_levels event that
        // lists a creator (the create-event sender or any additional_creators member)
        // in content.users MUST be rejected.
        // Spec: https://spec.matrix.org/v1.18/rooms/v12/
        if (policy.privilege_room_creators && new_users != nullptr)
        {
            for (auto const& user_entry : *new_users)
            {
                if (user_is_room_creator(auth_events.create, user_entry.key, policy))
                {
                    return make_denied("11", "creator cannot be specified in m.room.power_levels content.users");
                }
            }
        }

        // For m.room.power_levels, the sender must have the level to change each key.
        // Check that the sender can set the new event's content power levels.
        if (value_has_content(auth_events.power_levels))
        {
            auto const old_users = object_member_as_object(*value_is_object(auth_events.power_levels), "users");

            // Check users map: cannot elevate anyone above own level, cannot demote
            // anyone above own level.
            if (new_users != nullptr)
            {
                for (auto const& user_entry : *new_users)
                {
                    auto const* new_level = std::get_if<std::int64_t>(&user_entry.value->storage());
                    if (new_level == nullptr)
                    {
                        continue;
                    }
                    auto const old_level =
                        old_users == nullptr ? 0 : extract_user_level_from_users(*old_users, user_entry.key);
                    auto const user_old = old_level >= 0 ? old_level : 0;
                    if (*new_level > pl_sender_power && user_old <= pl_sender_power)
                    {
                        if (user_entry.key != *sender)
                        {
                            return make_denied("11", "cannot elevate user above own power level");
                        }
                    }
                    if (user_old > pl_sender_power && *new_level != user_old)
                    {
                        return make_denied("11", "cannot change power level of user above own power level");
                    }
                }
            }
        }

        auto const state_default = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "state_default", 50)
                                       : 50;
        if (pl_sender_power < state_default)
        {
            return make_denied("11", "insufficient power to send power_levels event");
        }

        return make_allowed("11");
    }

    if (*event_type == "m.room.redaction")
    {
        auto const redact_power = value_has_content(auth_events.power_levels)
                                      ? extract_power_level_key(auth_events.power_levels, "redact", 50)
                                      : 50;
        auto const ban_power = value_has_content(auth_events.power_levels)
                                   ? extract_power_level_key(auth_events.power_levels, "ban", 50)
                                   : 50;
        if (!user_can_redact(sender_power, redact_power, ban_power))
        {
            return make_denied("12", "insufficient power to redact");
        }
        return make_allowed("12");
    }

    // Step 13: state events require state_default power
    if (is_state_event)
    {
        auto const state_default = value_has_content(auth_events.power_levels)
                                       ? extract_power_level_key(auth_events.power_levels, "state_default", 50)
                                       : 50;

        // Check per-event-type power level in events map
        auto const events_state_level = value_has_content(auth_events.power_levels) ? [&]() -> std::int64_t {
            auto const* pl_obj = value_is_object(auth_events.power_levels);
            if (pl_obj == nullptr)
            {
                return state_default;
            }
            auto const* pl_content = object_member_as_object(*pl_obj, "content");
            if (pl_content == nullptr)
            {
                return state_default;
            }
            auto const* events = object_member_as_object(*pl_content, "events");
            if (events == nullptr)
            {
                return state_default;
            }
            auto const* level = integer_member(*events, *event_type);
            return level != nullptr ? *level : state_default;
        }()
            : state_default;

        if (sender_power < events_state_level)
        {
            return make_denied("13", "insufficient power for state event");
        }

        return make_allowed("13");
    }

    // Step 14: message events
    auto const events_default = value_has_content(auth_events.power_levels)
                                    ? extract_power_level_key(auth_events.power_levels, "events_default", 0)
                                    : 0;

    auto const events_message_level = value_has_content(auth_events.power_levels) ? [&]() -> std::int64_t {
        auto const* pl_obj = value_is_object(auth_events.power_levels);
        if (pl_obj == nullptr)
        {
            return events_default;
        }
        auto const* pl_content = object_member_as_object(*pl_obj, "content");
        if (pl_content == nullptr)
        {
            return events_default;
        }
        auto const* events = object_member_as_object(*pl_content, "events");
        if (events == nullptr)
        {
            return events_default;
        }
        auto const* level = integer_member(*events, *event_type);
        return level != nullptr ? *level : events_default;
    }()
        : events_default;

    if (sender_power < events_message_level)
    {
        return make_denied("14", "insufficient power for message event");
    }

    return make_allowed("14");
}

auto select_auth_events(EventAuthorizationRequest const& request) -> AuthEventSelection
{
    auto selection = AuthEventSelection{};

    // v12 (MSC4291): the create event is implicit in the room ID and MUST NOT be
    // listed in auth_events. For all earlier room versions create is always required.
    // Spec: https://spec.matrix.org/v1.18/rooms/v12/
    auto const* policy = rooms::find_room_version_policy(request.room_version);
    auto const create_is_implicit = (policy != nullptr && policy->create_event_is_room_id);

    if (!create_is_implicit)
    {
        selection.required.push_back({AuthEventKind::create, "m.room.create", ""});
    }

    if (requires_power_levels(request.event_type))
    {
        selection.required.push_back({AuthEventKind::power_levels, "m.room.power_levels", ""});
    }
    if (request.event_type == "m.room.member")
    {
        selection.required.push_back({AuthEventKind::join_rules, "m.room.join_rules", ""});
        selection.required.push_back({AuthEventKind::member, "m.room.member", request.state_key});
    }
    if (request.membership.third_party_invite)
    {
        selection.required.push_back(
            {AuthEventKind::third_party_invite, "m.room.third_party_invite", request.state_key});
    }

    return selection;
}

auto auth_event_kind_name(AuthEventKind kind) noexcept -> char const*
{
    switch (kind)
    {
    case AuthEventKind::create:
        return "create";
    case AuthEventKind::power_levels:
        return "power_levels";
    case AuthEventKind::join_rules:
        return "join_rules";
    case AuthEventKind::member:
        return "member";
    case AuthEventKind::third_party_invite:
        return "third_party_invite";
    }

    return "unknown";
}

auto auth_chain_contains(AuthChain const& chain, std::string_view event_id) noexcept -> bool
{
    return std::ranges::any_of(chain.event_ids, [event_id](std::string const& existing) {
        return existing == event_id;
    });
}

auto append_auth_chain_event(AuthChain& chain, std::string_view event_id) -> void
{
    if (!event_id.empty() && !auth_chain_contains(chain, event_id))
    {
        chain.event_ids.push_back(std::string{event_id});
    }
}

} // namespace merovingian::events
