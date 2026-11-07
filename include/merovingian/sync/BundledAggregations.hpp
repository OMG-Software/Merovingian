// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/HistoryVisibility.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::sync
{

// The most children of one kind of one event a bundled aggregation looks at, newest first
// (ADR-0430). Every served event costs at most this many index entries per kind, however many
// relations point at it, and one kind never uses up another's; beyond it `count` and `chunk`
// describe the newest children only.
inline constexpr std::size_t max_aggregated_children_examined{2048U};
// The most `m.replace` candidates one event parses: an edit is chosen by `origin_server_ts`, which
// is in the child's JSON. Candidates are the original sender's own edits, newest first.
inline constexpr std::size_t max_aggregated_edits_parsed{64U};
// The most entries in an `m.reference` aggregation's `chunk`.
inline constexpr std::size_t max_reference_chunk_entries{100U};

// Bundled aggregations (client-server-api.md, "Aggregations of child events"): `unsigned.m.relations`
// on an event served to a client, built from the children the table's relation index lists for it.
//
//   - `m.replace`: the most recent valid edit ("Validity of replacement events"), none for a
//     redacted original;
//   - `m.thread`: `latest_event`, `count` and `current_user_participated`;
//   - `m.reference`: `chunk` of the referencing events' IDs;
//   - `m.annotation` is never aggregated, nor is any rel_type the spec does not define one for.
//
// A child counts only when it is in the parent's room, is neither rejected nor soft-failed, was not
// sent by an ignored user, and the viewer may see it (HistoryVisibility): an aggregate never
// reveals an event the viewer could not read. A redacted child has lost its relation and is not
// listed. State events get no aggregation.
//
// One instance serves one request, for one viewer. It is not thread-safe and must not outlive the
// store, the visibility or the ignored set it was built with. The child serializer gives the
// client form of an event (the `m.replace` event, `latest_event`); the server builds it, so a
// stored `unsigned.m.relations` is never passed through.
class BundledAggregations final
{
public:
    using ChildSerializer = std::function<canonicaljson::Value(database::PersistentEvent const&)>;

    // `enabled` false makes apply() return the event unchanged (a /sync section that is not
    // `limited`).
    BundledAggregations(database::PersistentStore const& store, HistoryVisibility& visibility, std::string_view user_id,
                        std::unordered_set<std::string> const& ignored_senders, ChildSerializer serialize,
                        bool enabled = true);

    // `client_event` (the client form of `event`) with `unsigned.m.relations` set from its children,
    // replacing any it carried. Unchanged when it has no aggregatable child.
    [[nodiscard]] auto apply(database::PersistentEvent const& event, canonicaljson::Value client_event)
        -> canonicaljson::Value;

    // Index entries looked at so far, and child events parsed so far, by this instance.
    [[nodiscard]] auto children_examined() const noexcept -> std::size_t
    {
        return children_examined_;
    }
    [[nodiscard]] auto children_parsed() const noexcept -> std::size_t
    {
        return children_parsed_;
    }

private:
    [[nodiscard]] auto apply_at_depth(database::PersistentEvent const& event, canonicaljson::Value client_event,
                                      bool nested) -> canonicaljson::Value;
    [[nodiscard]] auto relations_of(database::PersistentEvent const& event, canonicaljson::Object const& client_event,
                                    bool nested) -> canonicaljson::Object;

    database::PersistentStore const& store_;
    HistoryVisibility& visibility_;
    std::string user_id_;
    std::unordered_set<std::string> const& ignored_senders_;
    ChildSerializer serialize_;
    bool enabled_;
    std::size_t children_examined_{0U};
    std::size_t children_parsed_{0U};
};

// Whether the child `candidate` is later in a thread than `current_latest` (`m.thread`
// `latest_event`: "the most recent event (topologically to the server)"): by depth, then by the
// order the server stored them.
[[nodiscard]] auto is_later_in_thread(database::PersistentEvent const& candidate,
                                      database::PersistentEvent const& current_latest) noexcept -> bool;

} // namespace merovingian::sync
