// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/redaction_service.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/RedactionContext.hpp"
#include "merovingian/events/RedactionVerdict.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/events/redaction_validity.hpp"
#include "merovingian/homeserver/LocalRedactionCheck.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto find_event(database::PersistentStore const& store, std::string_view event_id)
        -> database::PersistentEvent const*
    {
        auto const it = store.events.find(event_id);
        return it == store.events.end() ? nullptr : &*it;
    }

    [[nodiscard]] auto parse_event(std::string const& json) -> std::optional<canonicaljson::Value>
    {
        auto parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none ||
            std::get_if<canonicaljson::Object>(&parsed.value.storage()) == nullptr)
        {
            return std::nullopt;
        }
        return std::move(parsed.value);
    }

    [[nodiscard]] auto member_of(canonicaljson::Value const& value, std::string_view key) -> canonicaljson::Value const*
    {
        auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
        if (object == nullptr)
        {
            return nullptr;
        }
        for (auto const& member : *object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_of(canonicaljson::Value const& value, std::string_view key) -> std::optional<std::string>
    {
        auto const* member = member_of(value, key);
        auto const* text = member == nullptr ? nullptr : std::get_if<std::string>(&member->storage());
        return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
    }

    // The room's current m.room.create event, which never changes once set.
    [[nodiscard]] auto create_event_of(database::PersistentStore const& store, std::string_view room_id)
        -> database::PersistentEvent const*
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.create", "");
        return event_id.has_value() ? find_event(store, *event_id) : nullptr;
    }

    // The room version's policy, from the room's m.room.create event. nullptr when the room or its
    // version is unknown, in which case nothing is judged or applied.
    [[nodiscard]] auto policy_of(database::PersistentStore const& store, std::string_view room_id)
        -> rooms::RoomVersionPolicy const*
    {
        return stored_room_version_policy(store, room_id);
    }

    [[nodiscard]] auto context_with_create_event(database::PersistentStore const& store, std::string_view room_id)
        -> events::RedactionContext
    {
        auto context = events::RedactionContext{};
        if (auto const* create = create_event_of(store, room_id); create != nullptr)
        {
            if (auto parsed = parse_event(create->json); parsed.has_value())
            {
                context.create = std::move(*parsed);
            }
        }
        return context;
    }

    // Reads the power levels event a state lookup named. State naming an event the store cannot give back
    // is state this server does not have.
    auto load_power_levels(database::PersistentStore const& store, std::string_view event_id,
                           events::RedactionContext& context) -> void
    {
        auto const* stored = find_event(store, event_id);
        auto parsed = stored == nullptr ? std::nullopt : parse_event(stored->json);
        if (!parsed.has_value())
        {
            context.power_levels_known = false;
            return;
        }
        context.power_levels = std::move(*parsed);
    }

    // The room's power levels now.
    [[nodiscard]] auto current_context(database::PersistentStore const& store, std::string_view room_id)
        -> events::RedactionContext
    {
        auto context = context_with_create_event(store, room_id);
        if (auto const id = database::find_current_state_event_id(store, room_id, "m.room.power_levels", "");
            id.has_value())
        {
            load_power_levels(store, *id, context);
        }
        return context;
    }

    // The room's power levels when the redaction was sent, from the state this server recorded for it (a
    // redaction changes no state, so its group is the state before it too). Until that group is recorded, or
    // if its chain is broken, the levels are unknown.
    [[nodiscard]] auto context_before_event(database::PersistentStore const& store, std::string_view event_id,
                                            std::string_view room_id) -> events::RedactionContext
    {
        auto context = context_with_create_event(store, room_id);
        auto const group_id = database::find_event_state_group(store, event_id);
        auto const power_levels_id =
            group_id.has_value()
                ? database::find_state_group_state_event_id(store, *group_id, "m.room.power_levels", "")
                : std::nullopt;
        if (!power_levels_id.has_value())
        {
            context.power_levels_known = false;
            return context;
        }
        if (!power_levels_id->empty())
        {
            load_power_levels(store, *power_levels_id, context);
        }
        return context;
    }

    // Judges one withheld redaction and applies it if it applies. Leaves it withheld otherwise: it
    // may be waiting for its target, or may never apply.
    auto reconcile_redaction(database::PersistentStore& store, std::string const& redaction_id) -> void
    {
        if (!database::redaction_is_withheld(store, redaction_id))
        {
            return;
        }
        auto const* redaction_event = find_event(store, redaction_id);
        if (redaction_event == nullptr || redaction_event->status == "rejected" ||
            redaction_event->status == "soft_failed")
        {
            return;
        }
        auto const* policy = policy_of(store, redaction_event->room_id);
        auto const redaction = parse_event(redaction_event->json);
        if (policy == nullptr || !redaction.has_value())
        {
            return;
        }
        auto const target_id = events::redaction_target(*redaction, *policy);
        auto const* target_event = target_id.has_value() ? find_event(store, *target_id) : nullptr;
        // Not received yet: wait for it (rooms/v3.md "Handling redactions"). One from another room
        // can never be this redaction's partner.
        if (target_event == nullptr || target_event->room_id != redaction_event->room_id)
        {
            return;
        }
        auto const target = parse_event(target_event->json);
        if (!target.has_value())
        {
            return;
        }
        // The sender's authority comes from this server's record of the room, never from the power levels the
        // event cites: it must hold at the redaction and still hold now (ADR-0586). The domain condition needs
        // neither, so a redaction of a user's own server is not held back by unknown state.
        auto const applies_under = [&](events::RedactionContext const& context) {
            return events::judge_redaction(*redaction, *target, context, *policy) == events::RedactionVerdict::applies;
        };
        if (!applies_under(context_before_event(store, redaction_id, redaction_event->room_id)) ||
            !applies_under(current_context(store, redaction_event->room_id)))
        {
            return;
        }

        auto const redacted = events::redact_event(*target, *policy);
        if (!redacted.error.empty())
        {
            return;
        }
        auto const serialized = canonicaljson::serialize_canonical(redacted.event);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return;
        }
        auto const target_event_id = target_event->event_id;
        if (serialized.output != target_event->json &&
            !database::replace_event_json(store, target_event_id, serialized.output))
        {
            observability::log_diagnostic(
                "redaction", "redaction.apply_failed",
                {
                    {"redaction_event_id", redaction_id,    false},
                    {"target_event_id",    target_event_id, false}
            },
                observability::LogEventSeverity::warning);
            return;
        }
        database::mark_redaction_applied(store, redaction_id, target_event_id);
        observability::log_diagnostic(
            "redaction", "redaction.applied",
            {
                {"redaction_event_id", redaction_id,    false},
                {"target_event_id",    target_event_id, false}
        });
    }

} // namespace

auto reconcile_redactions_for_event(database::PersistentStore& store, std::string_view event_id) -> void
{
    // The event as a redaction, then every stored redaction that names it as their target.
    reconcile_redaction(store, std::string{event_id});
    for (auto const& redaction_id : database::redactions_naming(store, event_id))
    {
        reconcile_redaction(store, redaction_id);
    }
}

auto reconcile_all_redactions(database::PersistentStore& store) -> std::size_t
{
    auto const withheld = std::vector<std::string>{store.redactions.withheld.begin(), store.redactions.withheld.end()};
    auto applied = std::size_t{0U};
    for (auto const& redaction_id : withheld)
    {
        reconcile_redaction(store, redaction_id);
        if (!database::redaction_is_withheld(store, redaction_id))
        {
            ++applied;
        }
    }
    return applied;
}

auto install_redaction_reconciler(database::PersistentStore& store) -> void
{
    store.redaction_observer = [](database::PersistentStore& observed, std::string const& event_id) {
        reconcile_redactions_for_event(observed, event_id);
    };
}

auto check_local_redaction(database::PersistentStore const& store, std::string_view room_id,
                           std::string_view composed_redaction_json, bool sender_is_server_admin,
                           std::string_view local_server_name) -> LocalRedactionCheck
{
    auto const* policy = policy_of(store, room_id);
    auto const redaction = parse_event(std::string{composed_redaction_json});
    if (policy == nullptr || !redaction.has_value())
    {
        return LocalRedactionCheck::forbidden;
    }
    auto const target_id = events::redaction_target(*redaction, *policy);
    auto const* target_event = target_id.has_value() ? find_event(store, *target_id) : nullptr;
    if (target_event != nullptr && target_event->room_id != room_id)
    {
        return LocalRedactionCheck::target_unknown;
    }
    if (target_event == nullptr)
    {
        // Spec (PUT /redact): the only response is 200. An event this server has not received (it
        // may be held by the servers the redaction will reach, or arrive later) cannot be judged
        // here, and whose event it is cannot be checked, so only a sender who may redact anyone's
        // event is let through; the target's own sender, its domain and the rest of the rules are
        // judged when it arrives (reconcile_redaction).
        return target_id.has_value() && !target_id->empty() &&
                       events::sender_meets_redact_level(*redaction, current_context(store, room_id), *policy)
                   ? LocalRedactionCheck::permitted
                   : LocalRedactionCheck::forbidden;
    }
    auto const target = parse_event(target_event->json);
    auto const sender = string_of(*redaction, "sender");
    if (!target.has_value() || !sender.has_value())
    {
        return LocalRedactionCheck::forbidden;
    }

    auto const context = current_context(store, room_id);
    auto const target_sender = string_of(*target, "sender");
    auto const own_event = target_sender == sender;
    auto const server_admin_over_local_user =
        sender_is_server_admin && target_sender.has_value() && events::domain_of(*target_sender) == local_server_name;
    if (!own_event && !server_admin_over_local_user && !events::sender_meets_redact_level(*redaction, context, *policy))
    {
        return LocalRedactionCheck::forbidden;
    }
    // Whoever may send it, a redaction that would not then be applied is not sent.
    return events::judge_redaction(*redaction, *target, context, *policy) == events::RedactionVerdict::applies
               ? LocalRedactionCheck::permitted
               : LocalRedactionCheck::forbidden;
}

} // namespace merovingian::homeserver
