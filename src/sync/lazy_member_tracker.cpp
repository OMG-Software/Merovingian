// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/sync/lazy_member_tracker.hpp"

#include <algorithm>
#include <functional>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

namespace merovingian::sync
{

namespace
{

    // Whether a client holding `since` has received everything up to the response whose `next_batch` is `token`.
    [[nodiscard]] auto covers(StreamToken since, StreamToken token) noexcept -> bool
    {
        return since.event_ordering >= token.event_ordering && since.membership_ordering >= token.membership_ordering &&
               since.sync_stream_id >= token.sync_stream_id;
    }

    [[nodiscard]] auto component_max(StreamToken left, StreamToken right) noexcept -> StreamToken
    {
        return {std::max(left.event_ordering, right.event_ordering),
                std::max(left.membership_ordering, right.membership_ordering),
                std::max(left.sync_stream_id, right.sync_stream_id)};
    }

    [[nodiscard]] auto same_token(StreamToken left, StreamToken right) noexcept -> bool
    {
        return left.event_ordering == right.event_ordering && left.membership_ordering == right.membership_ordering &&
               left.sync_stream_id == right.sync_stream_id;
    }

    // A string-keyed map whose entries are kept in order of use, most recent first. Not thread safe: the
    // tracker's mutex covers every use.
    template <typename Value>
    class LruMap final
    {
    public:
        using Item = std::pair<std::string, Value>;
        using List = std::list<Item>;

        // The entry for `key`, made most recent, or nothing.
        [[nodiscard]] auto find(std::string const& key) -> std::optional<std::reference_wrapper<Value>>
        {
            auto const found = index_.find(key);
            if (found == index_.end())
            {
                return std::nullopt;
            }
            items_.splice(items_.begin(), items_, found->second);
            return std::ref(found->second->second);
        }

        // The entry for `key`, created empty (and made most recent) when absent.
        [[nodiscard]] auto get_or_create(std::string const& key) -> Value&
        {
            if (auto existing = find(key); existing.has_value())
            {
                return existing->get();
            }
            items_.emplace_front(key, Value{});
            index_.emplace(key, items_.begin());
            return items_.front().second;
        }

        auto erase(std::string const& key) -> void
        {
            auto const found = index_.find(key);
            if (found == index_.end())
            {
                return;
            }
            items_.erase(found->second);
            index_.erase(found);
        }

        // Removes and returns the least recently used entry.
        [[nodiscard]] auto pop_oldest() -> Item
        {
            auto item = std::move(items_.back());
            index_.erase(item.first);
            items_.pop_back();
            return item;
        }

        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return items_.size();
        }

        [[nodiscard]] auto empty() const noexcept -> bool
        {
            return items_.empty();
        }

        [[nodiscard]] auto items() noexcept -> List&
        {
            return items_;
        }

        [[nodiscard]] auto items() const noexcept -> List const&
        {
            return items_;
        }

        auto rebuild_index() -> void
        {
            index_.clear();
            for (auto it = items_.begin(); it != items_.end(); ++it)
            {
                index_.emplace(it->first, it);
            }
        }

    private:
        List items_{};
        std::unordered_map<std::string, typename List::iterator> index_{};
    };

    struct MemberEntry final
    {
        std::string event_id{};
        StreamToken token{};
        // Recorded, and no request has yet presented exactly `token`: the client may never have received the response.
        // A later token does not prove receipt (a retried long-poll can answer after the aborted one, past its token),
        // so only an exact match settles an entry.
        bool pending{true};
    };

    using RoomMembers = LruMap<MemberEntry>;

    struct StreamState final
    {
        LruMap<RoomMembers> rooms{};
        // The component-wise maximum of every token recorded and still held (never lowered on eviction, so it
        // can only make a request scan when it need not).
        StreamToken highest{};
        std::size_t members{0U};
        // How many of the stream's entries are pending. While any is, a request must scan: `since` covering `highest`
        // proves nothing about them.
        std::size_t pending{0U};
    };

    [[nodiscard]] auto pending_in(RoomMembers const& room) -> std::size_t
    {
        return static_cast<std::size_t>(std::ranges::count_if(room.items(), [](RoomMembers::Item const& item) {
            return item.second.pending;
        }));
    }

    // Length-prefixed, so no (user, device, filter) triple can collide with another.
    [[nodiscard]] auto stream_key(LazyMemberTracker::StreamKey const& key) -> std::string
    {
        auto out = std::string{};
        out.reserve(key.user_id.size() + key.device_id.size() + key.filter.size() + 24U);
        out.append(std::to_string(key.user_id.size())).push_back(':');
        out.append(key.user_id);
        out.append(std::to_string(key.device_id.size())).push_back(':');
        out.append(key.device_id);
        out.append(key.filter);
        return out;
    }

} // namespace

struct LazyMemberTracker::State final
{
    explicit State(Limits configured)
        : limits{configured}
    {
    }

    Limits limits;
    LruMap<StreamState> streams{};
    std::size_t total_members{0U};

    [[nodiscard]] auto trackable(StreamKey const& key) const noexcept -> bool
    {
        return !key.device_id.empty() && key.filter.size() <= limits.max_filter_bytes;
    }

    auto drop_stream(std::string const& id) -> void
    {
        if (auto stream = streams.find(id); stream.has_value())
        {
            total_members -= stream->get().members;
        }
        streams.erase(id);
    }

    auto evict_to_total_cap() -> void
    {
        while (total_members > limits.max_tracked_members && !streams.empty())
        {
            auto oldest = streams.pop_oldest();
            total_members -= oldest.second.members;
        }
    }
};

LazyMemberTracker::LazyMemberTracker()
    : LazyMemberTracker(Limits{})
{
}

LazyMemberTracker::LazyMemberTracker(Limits limits)
    : state_{std::make_unique<State>(limits)}
{
}

LazyMemberTracker::~LazyMemberTracker() = default;

auto LazyMemberTracker::begin_request(StreamKey const& key, std::optional<StreamToken> since) -> void
{
    auto const lock = std::scoped_lock{mutex_};
    if (!state_->trackable(key))
    {
        return;
    }
    auto const id = stream_key(key);
    if (!since.has_value())
    {
        state_->drop_stream(id);
        return;
    }
    auto found = state_->streams.find(id);
    if (!found.has_value())
    {
        return;
    }
    auto& stream = found->get();
    if (stream.pending == 0U && covers(*since, stream.highest))
    {
        return;
    }
    // A pending entry is settled by a request presenting exactly its token and deleted by any other: the client
    // presented some other response's token, so it cannot be shown to hold this one. A settled entry stays while
    // `since` covers it; one `since` does not cover is deleted (a retry of an older token).
    auto highest = StreamToken{};
    auto remaining = std::size_t{0U};
    for (auto room = stream.rooms.items().begin(); room != stream.rooms.items().end();)
    {
        auto& members = room->second;
        for (auto member = members.items().begin(); member != members.items().end();)
        {
            auto& entry = member->second;
            if (entry.pending && same_token(*since, entry.token))
            {
                entry.pending = false;
            }
            if (!entry.pending && covers(*since, entry.token))
            {
                highest = component_max(highest, entry.token);
                ++remaining;
                ++member;
            }
            else
            {
                member = members.items().erase(member);
            }
        }
        members.rebuild_index();
        if (members.empty())
        {
            room = stream.rooms.items().erase(room);
        }
        else
        {
            ++room;
        }
    }
    stream.rooms.rebuild_index();
    state_->total_members -= stream.members - remaining;
    stream.members = remaining;
    stream.pending = 0U;
    stream.highest = highest;
    if (remaining == 0U)
    {
        state_->streams.erase(id);
    }
}

auto LazyMemberTracker::is_acknowledged(StreamKey const& key, std::string_view room_id, std::string_view member_user_id,
                                        std::string_view event_id, StreamToken since) -> bool
{
    auto const lock = std::scoped_lock{mutex_};
    if (!state_->trackable(key))
    {
        return false;
    }
    auto stream = state_->streams.find(stream_key(key));
    if (!stream.has_value())
    {
        return false;
    }
    auto room = stream->get().rooms.find(std::string{room_id});
    if (!room.has_value())
    {
        return false;
    }
    auto entry = room->get().find(std::string{member_user_id});
    return entry.has_value() && !entry->get().pending && entry->get().event_id == event_id &&
           covers(since, entry->get().token);
}

auto LazyMemberTracker::record(StreamKey const& key, std::string_view room_id, std::span<SentMember const> members,
                               StreamToken next_batch, std::optional<StreamToken> since) -> void
{
    if (members.empty() || (since.has_value() && same_token(*since, next_batch)))
    {
        return;
    }
    auto const lock = std::scoped_lock{mutex_};
    if (!state_->trackable(key) || state_->limits.max_keys == 0U || state_->limits.max_rooms_per_key == 0U ||
        state_->limits.max_members_per_room == 0U)
    {
        return;
    }
    auto const id = stream_key(key);
    auto& stream = state_->streams.get_or_create(id);
    stream.highest = component_max(stream.highest, next_batch);
    auto& room = stream.rooms.get_or_create(std::string{room_id});
    for (auto const& member : members)
    {
        auto const user = std::string{member.user_id};
        if (auto existing = room.find(user); existing.has_value())
        {
            // Sent again: whatever it was, it is now the carrier of a response the client has not yet presented.
            if (!existing->get().pending)
            {
                ++stream.pending;
            }
            existing->get() = MemberEntry{std::string{member.event_id}, next_batch, true};
            continue;
        }
        room.get_or_create(user) = MemberEntry{std::string{member.event_id}, next_batch, true};
        ++stream.members;
        ++stream.pending;
        ++state_->total_members;
        while (room.size() > state_->limits.max_members_per_room)
        {
            auto const evicted = room.pop_oldest();
            if (evicted.second.pending)
            {
                --stream.pending;
            }
            --stream.members;
            --state_->total_members;
        }
    }
    while (stream.rooms.size() > state_->limits.max_rooms_per_key)
    {
        auto evicted = stream.rooms.pop_oldest();
        stream.pending -= pending_in(evicted.second);
        stream.members -= evicted.second.size();
        state_->total_members -= evicted.second.size();
    }
    while (state_->streams.size() > state_->limits.max_keys)
    {
        auto oldest = state_->streams.pop_oldest();
        state_->total_members -= oldest.second.members;
    }
    state_->evict_to_total_cap();
}

auto LazyMemberTracker::key_count() const -> std::size_t
{
    auto const lock = std::scoped_lock{mutex_};
    return state_->streams.size();
}

auto LazyMemberTracker::member_count() const -> std::size_t
{
    auto const lock = std::scoped_lock{mutex_};
    return state_->total_members;
}

} // namespace merovingian::sync
