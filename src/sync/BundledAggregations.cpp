// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/BundledAggregations.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/trust_safety/ignore_list.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::sync
{

namespace
{

    using database::PersistentEvent;
    using database::RelationKind;

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key)
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

    [[nodiscard]] auto string_of(canonicaljson::Object const& object, std::string_view key) -> std::string const*
    {
        auto const* value = member_of(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto object_of(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Object const*
    {
        auto const* value = member_of(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    // The `rel_type` of the event's own `content."m.relates_to"`, or nullptr.
    [[nodiscard]] auto own_rel_type(canonicaljson::Object const& event) -> std::string const*
    {
        auto const* content = object_of(event, "content");
        auto const* relates = content == nullptr ? nullptr : object_of(*content, "m.relates_to");
        return relates == nullptr ? nullptr : string_of(*relates, "rel_type");
    }

    // A child can be aggregated only if it is in the parent's room and was not refused (ADR-0064:
    // rejected and soft-failed events are never relayed, so never counted).
    [[nodiscard]] auto counts_towards(PersistentEvent const& parent, PersistentEvent const& child) noexcept -> bool
    {
        return child.room_id == parent.room_id && child.status != "rejected" && child.status != "soft_failed";
    }

    struct EditCandidate final
    {
        std::reference_wrapper<PersistentEvent const> row;
        std::int64_t origin_server_ts{0};
    };

} // namespace

auto is_later_in_thread(PersistentEvent const& candidate, PersistentEvent const& current_latest) noexcept -> bool
{
    return std::tie(candidate.depth, candidate.stream_ordering) >
           std::tie(current_latest.depth, current_latest.stream_ordering);
}

BundledAggregations::BundledAggregations(database::PersistentStore const& store, HistoryVisibility& visibility,
                                         std::string_view user_id,
                                         std::unordered_set<std::string> const& ignored_senders,
                                         ChildSerializer serialize, bool enabled)
    : store_{store}
    , visibility_{visibility}
    , user_id_{user_id}
    , ignored_senders_{ignored_senders}
    , serialize_{std::move(serialize)}
    , enabled_{enabled}
{
}

auto BundledAggregations::relations_of(PersistentEvent const& event, canonicaljson::Object const& client_event,
                                       bool nested) -> canonicaljson::Object
{
    // Spec: "State events do not currently receive bundled aggregations."
    if (member_of(client_event, "state_key") != nullptr)
    {
        return {};
    }
    if (store_.events.relation_child_count(event.event_id) == 0U)
    {
        return {};
    }

    // The original can have an `m.replace` bundle only if it is not itself an edit and is not
    // redacted ("Server-side aggregation of m.replace relationships").
    auto const* original_type = string_of(client_event, "type");
    auto const* original_rel = own_rel_type(client_event);
    auto const may_be_edited = original_type != nullptr && (original_rel == nullptr || *original_rel != "m.replace") &&
                               !database::applied_redaction_of(store_, event.event_id).has_value();

    auto edits = std::vector<EditCandidate>{};
    auto thread_count = std::int64_t{0};
    auto latest_in_thread = std::optional<std::reference_wrapper<PersistentEvent const>>{};
    // Spec: participated when the viewer sent the root or sent a child of it.
    auto participated = event.sender_user_id == user_id_;
    auto references = std::vector<std::reference_wrapper<PersistentEvent const>>{};

    // Spec: "Servers must additionally ensure they do not consider child events from ignored users
    // when preparing an aggregation for the client."
    auto const ignored = [this](PersistentEvent const& child) {
        return trust_safety::is_delivery_suppressed(ignored_senders_, child.sender_user_id, false);
    };

    // Each kind is walked on its own, with its own window, so a long thread or a flood of references
    // can never push an edit out of the bundle (ADR-0430).
    if (may_be_edited)
    {
        auto const walk = store_.events.for_each_relation_child_newest_first(
            event.event_id, RelationKind::replace,
            [&](PersistentEvent const& child) {
                // Only the original sender's edits are valid; a stranger's cost nothing to skip.
                if (counts_towards(event, child) && !ignored(child) && child.sender_user_id == event.sender_user_id &&
                    edits.size() < max_aggregated_edits_parsed)
                {
                    edits.push_back({std::cref(child), 0});
                }
            },
            max_aggregated_children_examined);
        children_examined_ += walk.examined;
    }
    {
        auto const walk = store_.events.for_each_relation_child_newest_first(
            event.event_id, RelationKind::thread,
            [&](PersistentEvent const& child) {
                if (!counts_towards(event, child))
                {
                    return;
                }
                if (child.sender_user_id == user_id_)
                {
                    participated = true;
                }
                if (ignored(child) || !visibility_.can_see(child))
                {
                    return;
                }
                ++thread_count;
                if (!latest_in_thread.has_value() || is_later_in_thread(child, latest_in_thread->get()))
                {
                    latest_in_thread = std::cref(child);
                }
            },
            max_aggregated_children_examined);
        children_examined_ += walk.examined;
    }
    {
        auto const walk = store_.events.for_each_relation_child_newest_first(
            event.event_id, RelationKind::reference,
            [&](PersistentEvent const& child) {
                if (references.size() < max_reference_chunk_entries && counts_towards(event, child) &&
                    !ignored(child) && visibility_.can_see(child))
                {
                    references.push_back(std::cref(child));
                }
            },
            max_aggregated_children_examined);
        children_examined_ += walk.examined;
    }

    auto relations = canonicaljson::Object{};

    // m.replace: the most recent valid replacement, by origin_server_ts then the lexicographically
    // largest event_id; one the viewer may not see is passed over for the next most recent.
    auto valid_edits = std::vector<EditCandidate>{};
    for (auto& edit : edits)
    {
        ++children_parsed_;
        auto const parsed = canonicaljson::parse_lossless(edit.row.get().json);
        auto const* object = parsed.error == canonicaljson::ParseError::none
                                 ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                 : nullptr;
        if (object == nullptr)
        {
            continue;
        }
        auto const* type = string_of(*object, "type");
        auto const* ts_value = member_of(*object, "origin_server_ts");
        auto const* ts = ts_value == nullptr ? nullptr : std::get_if<std::int64_t>(&ts_value->storage());
        auto const* content = object_of(*object, "content");
        // "The replacement and original events must have the same type", no `state_key` on either,
        // and the replacement "must have an m.new_content property" (once decrypted: the payload of
        // an encrypted event is not the server's to read).
        auto const new_content_ok = content != nullptr && (object_of(*content, "m.new_content") != nullptr ||
                                                           *original_type == "m.room.encrypted");
        if (type == nullptr || *type != *original_type || ts == nullptr || member_of(*object, "state_key") != nullptr ||
            !new_content_ok)
        {
            continue;
        }
        edit.origin_server_ts = *ts;
        valid_edits.push_back(edit);
    }
    std::ranges::sort(valid_edits, [](EditCandidate const& lhs, EditCandidate const& rhs) {
        return std::tie(lhs.origin_server_ts, lhs.row.get().event_id) >
               std::tie(rhs.origin_server_ts, rhs.row.get().event_id);
    });
    for (auto const& edit : valid_edits)
    {
        if (visibility_.can_see(edit.row.get()))
        {
            relations.push_back(canonicaljson::make_member("m.replace", serialize_(edit.row.get())));
            break;
        }
    }

    if (latest_in_thread.has_value())
    {
        auto latest = serialize_(latest_in_thread->get());
        // "child events of the latest_event should themselves be aggregated". One level only: the
        // nested event's own bundle never nests again, so a loop in the data cannot recurse.
        if (!nested)
        {
            latest = apply_at_depth(latest_in_thread->get(), std::move(latest), true);
        }
        auto bundle = canonicaljson::Object{};
        bundle.push_back(canonicaljson::make_member("latest_event", std::move(latest)));
        bundle.push_back(canonicaljson::make_member("count", canonicaljson::Value{thread_count}));
        bundle.push_back(canonicaljson::make_member("current_user_participated", canonicaljson::Value{participated}));
        relations.push_back(canonicaljson::make_member("m.thread", canonicaljson::Value{std::move(bundle)}));
    }

    if (!references.empty())
    {
        std::ranges::sort(references, [](PersistentEvent const& lhs, PersistentEvent const& rhs) {
            return std::tie(lhs.stream_ordering, lhs.event_id) < std::tie(rhs.stream_ordering, rhs.event_id);
        });
        auto chunk = canonicaljson::Array{};
        chunk.reserve(references.size());
        for (PersistentEvent const& reference : references)
        {
            auto entry = canonicaljson::Object{};
            entry.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{reference.event_id}));
            chunk.push_back(canonicaljson::Value{std::move(entry)});
        }
        auto bundle = canonicaljson::Object{};
        bundle.push_back(canonicaljson::make_member("chunk", canonicaljson::Value{std::move(chunk)}));
        relations.push_back(canonicaljson::make_member("m.reference", canonicaljson::Value{std::move(bundle)}));
    }
    return relations;
}

auto BundledAggregations::apply(PersistentEvent const& event, canonicaljson::Value client_event) -> canonicaljson::Value
{
    return apply_at_depth(event, std::move(client_event), false);
}

auto BundledAggregations::apply_at_depth(PersistentEvent const& event, canonicaljson::Value client_event, bool nested)
    -> canonicaljson::Value
{
    if (!enabled_)
    {
        return client_event;
    }
    auto const* object = std::get_if<canonicaljson::Object>(&client_event.storage());
    if (object == nullptr)
    {
        return client_event;
    }
    auto relations = relations_of(event, *object, nested);
    if (relations.empty())
    {
        return client_event;
    }

    auto result = canonicaljson::Object{};
    auto merged = canonicaljson::Object{};
    for (auto const& member : *object)
    {
        if (member.key != "unsigned")
        {
            result.push_back(member);
            continue;
        }
        if (auto const* existing = std::get_if<canonicaljson::Object>(&member.value->storage()); existing != nullptr)
        {
            for (auto const& entry : *existing)
            {
                if (entry.key != "m.relations")
                {
                    merged.push_back(entry);
                }
            }
        }
    }
    merged.push_back(canonicaljson::make_member("m.relations", canonicaljson::Value{std::move(relations)}));
    result.push_back(canonicaljson::make_member("unsigned", canonicaljson::Value{std::move(merged)}));
    return canonicaljson::Value{std::move(result)};
}

} // namespace merovingian::sync
