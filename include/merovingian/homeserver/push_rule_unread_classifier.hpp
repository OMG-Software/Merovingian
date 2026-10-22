// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/push_room_facts.hpp"
#include "merovingian/push/push_rules.hpp"
#include "merovingian/sync/history_visibility.hpp"
#include "merovingian/sync/unread_event_classifier.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// The Push Gateway API's `counts.unread` saturates here (ADR-0207): "the number of unread messages
// a user has across all of the rooms they are a member of" is a badge, and a client showing 1000 or
// more shows "lots". The count runs under runtime.mutex for every recipient of every notifying
// event, so its work must not grow with the recipient's backlog. At most
// push_badge_unread_examined_cap unread events are parsed and classified; a count that runs out of
// examinations first reports what it found.
inline constexpr auto push_badge_unread_cap = std::uint32_t{1000U};
inline constexpr auto push_badge_unread_examined_cap = std::uint64_t{4000U};

// `user_id`'s badge count across their joined rooms, by `ruleset` (the rules delivery already
// loaded for them), bounded as above. Call with runtime.mutex held.
[[nodiscard]] auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                                           push::PushRuleset const& ruleset) -> std::uint32_t;

// Counts an unread event by `user`'s push rules (R15, ADR-0205). Spec ("Receiving notifications"):
// "Notifications are determined by the push rules which apply to an event". The ruleset is
// loaded once, at construction (homeserver::load_push_ruleset); each room's facts, the user's
// display name in it and the start of the user's current join are computed the first time the
// room is asked about.
//
// Only events after the user's current join are counted. Earlier events are history the user
// may not be allowed to see, and a content rule counted over them would reveal whether they
// contain a word (ADR-0205).
//
// Borrows `store`, which must outlive it and not change while it is used; build one per request,
// under runtime.mutex, and do not share it between threads.
class PushRuleUnreadClassifier final : public sync::UnreadEventClassifier
{
public:
    PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user, std::size_t max_user_rules);
    // With `ruleset` already loaded for `user` (load_push_ruleset), so a caller that has it does not
    // read and validate the user's rules a second time under runtime.mutex.
    PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user, push::PushRuleset ruleset);
    // With the request's own `visibility` filter, so its indexes are built once per request; the
    // constructors above build a filter of their own.
    PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user, std::size_t max_user_rules,
                             sync::HistoryVisibility& visibility);

    // `visibility_` may refer to this object's own `owned_visibility_`, so a copy or move would
    // leave it referring to the source. Build one in place, where it is used.
    PushRuleUnreadClassifier(PushRuleUnreadClassifier const&) = delete;
    PushRuleUnreadClassifier(PushRuleUnreadClassifier&&) = delete;
    auto operator=(PushRuleUnreadClassifier const&) -> PushRuleUnreadClassifier& = delete;
    auto operator=(PushRuleUnreadClassifier&&) -> PushRuleUnreadClassifier& = delete;
    ~PushRuleUnreadClassifier() override = default;

    [[nodiscard]] auto visible(database::PersistentEvent const& event) const -> bool override;

    [[nodiscard]] auto counted_after(std::string_view room_id) const -> std::optional<std::uint64_t> override;
    [[nodiscard]] auto classify(std::string_view room_id, canonicaljson::Value const& event) const
        -> sync::UnreadEventOutcome override;

private:
    struct RoomFacts final
    {
        PushRoomFacts push{};
        std::string display_name{};
        std::optional<std::uint64_t> joined_after{};
    };

    [[nodiscard]] auto room(std::string_view room_id) const -> RoomFacts const&;

    std::reference_wrapper<database::PersistentStore const> store_;
    std::string user_;
    push::PushRuleset ruleset_;
    // The filter a caller lent, or one of this classifier's own. Declared before `visibility_`,
    // which may refer to it.
    std::optional<sync::HistoryVisibility> owned_visibility_;
    std::reference_wrapper<sync::HistoryVisibility> visibility_;
    mutable std::map<std::string, RoomFacts, std::less<>> rooms_{};
};

// The stream position of the event that began `user`'s current join of `room_id`: the earliest
// m.room.member join of theirs with no later non-join membership. nullopt when they are not
// joined. A profile change re-sends a join, which does not restart the span.
[[nodiscard]] auto current_join_start(database::PersistentStore const& store, std::string_view room_id,
                                      std::string_view user) -> std::optional<std::uint64_t>;

} // namespace merovingian::homeserver
