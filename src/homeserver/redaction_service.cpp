// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/redaction_service.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/events/redaction_validity.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
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
        auto const it = std::ranges::find_if(store.events, [event_id](database::PersistentEvent const& event) {
            return event.event_id == event_id;
        });
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
        auto const it = std::ranges::find_if(store.state, [room_id](database::PersistentStateEvent const& state) {
            return state.room_id == room_id && state.event_type == "m.room.create" && state.state_key.empty();
        });
        return it == store.state.end() ? nullptr : find_event(store, it->event_id);
    }

    // The room version's policy, from the room's m.room.create event. nullptr when the room or its
    // version is unknown, in which case nothing is judged or applied.
    [[nodiscard]] auto policy_of(database::PersistentStore const& store, std::string_view room_id)
        -> rooms::RoomVersionPolicy const*
    {
        auto const* create = create_event_of(store, room_id);
        if (create == nullptr)
        {
            return nullptr;
        }
        auto const parsed = parse_event(create->json);
        auto const* content = parsed.has_value() ? member_of(*parsed, "content") : nullptr;
        auto const version = content == nullptr ? std::nullopt : string_of(*content, "room_version");
        return rooms::find_room_version_policy(version.value_or("1"));
    }

    // What the redaction was authorized against: the power levels among its own auth_events (the
    // room's state as the redaction's sender saw it), and the room's create event.
    [[nodiscard]] auto context_of(database::PersistentStore const& store, canonicaljson::Value const& redaction,
                                  std::string_view room_id) -> events::RedactionContext
    {
        auto context = events::RedactionContext{};
        if (auto const* create = create_event_of(store, room_id); create != nullptr)
        {
            if (auto parsed = parse_event(create->json); parsed.has_value())
            {
                context.create = std::move(*parsed);
            }
        }
        auto const* auth_events = member_of(redaction, "auth_events");
        auto const* ids = auth_events == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&auth_events->storage());
        if (ids == nullptr)
        {
            return context;
        }
        for (auto const& id : *ids)
        {
            auto const* text = std::get_if<std::string>(&id.storage());
            auto const* stored = text == nullptr ? nullptr : find_event(store, *text);
            if (stored == nullptr)
            {
                continue;
            }
            auto parsed = parse_event(stored->json);
            if (parsed.has_value() && string_of(*parsed, "type") == std::optional<std::string>{"m.room.power_levels"})
            {
                context.power_levels = std::move(*parsed);
                break;
            }
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
        if (!target.has_value() ||
            events::judge_redaction(*redaction, *target, context_of(store, *redaction, redaction_event->room_id),
                                    *policy) != events::RedactionVerdict::applies)
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
    if (target_event == nullptr || target_event->room_id != room_id)
    {
        return LocalRedactionCheck::target_unknown;
    }
    auto const target = parse_event(target_event->json);
    auto const sender = string_of(*redaction, "sender");
    if (!target.has_value() || !sender.has_value())
    {
        return LocalRedactionCheck::forbidden;
    }

    auto const context = context_of(store, *redaction, room_id);
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
