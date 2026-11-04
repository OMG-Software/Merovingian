// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/sync/lazy_member_tracker.hpp"

#include <algorithm>
#include <list>
#include <unordered_map>
#include <utility>

namespace merovingian::sync
{

namespace
{

// Whether a client holding `since` has received the response whose `next_batch` is `token`.
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
template <typename Value> class LruMap final
{
public:
    using Item = std::pair<std::string, Value>;
    using List = std::list<Item>;

    [[nodiscard]] auto find(std::string const& key) -> Value*
    {
        auto const found = index_.find(key);
        if (found == index_.end())
        {
            return nullptr;
        }
        items_.splice(items_.begin(), items_, found->second);
        return &found->second->second;
    }

    // The entry for `key`, created empty (and made most recent) when absent.
    [[nodiscard]] auto get_or_create(std::string const& key) -> Value&
    {
        if (auto* existing = find(key); existing != nullptr)
        {
            return *existing;
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
};

using RoomMembers = LruMap<MemberEntry>;

struct StreamState final
{
    LruMap<RoomMembers> rooms{};
    // The component-wise maximum of every token recorded and still held (never lowered on eviction, so it
    // can only make a request scan when it need not). A `since` that covers it covers every entry.
    StreamToken highest{};
    std::size_t members{0U};
};

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
        if (auto* stream = streams.find(id); stream != nullptr)
        {
            total_members -= stream->members;
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
    auto* stream = state_->streams.find(id);
    if (stream == nullptr || covers(*since, stream->highest))
    {
        return;
    }
    // Some entry is not covered: the client presented a token older than a response it was sent, so it
    // never received that response. Delete what `since` does not cover.
    auto highest = StreamToken{};
    auto remaining = std::size_t{0U};
    for (auto room = stream->rooms.items().begin(); room != stream->rooms.items().end();)
    {
        auto& members = room->second;
        for (auto member = members.items().begin(); member != members.items().end();)
        {
            if (covers(*since, member->second.token))
            {
                highest = component_max(highest, member->second.token);
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
            room = stream->rooms.items().erase(room);
        }
        else
        {
            ++room;
        }
    }
    stream->rooms.rebuild_index();
    state_->total_members -= stream->members - remaining;
    stream->members = remaining;
    stream->highest = highest;
    if (remaining == 0U)
    {
        state_->streams.erase(id);
    }
}

auto LazyMemberTracker::is_acknowledged(StreamKey const& key, std::string_view room_id,
                                        std::string_view member_user_id, std::string_view event_id, StreamToken since)
    -> bool
{
    auto const lock = std::scoped_lock{mutex_};
    if (!state_->trackable(key))
    {
        return false;
    }
    auto* stream = state_->streams.find(stream_key(key));
    if (stream == nullptr)
    {
        return false;
    }
    auto* room = stream->rooms.find(std::string{room_id});
    if (room == nullptr)
    {
        return false;
    }
    auto* entry = room->find(std::string{member_user_id});
    return entry != nullptr && entry->event_id == event_id && covers(since, entry->token);
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
        if (auto* existing = room.find(user); existing != nullptr)
        {
            existing->event_id = std::string{member.event_id};
            existing->token = next_batch;
            continue;
        }
        room.get_or_create(user) = MemberEntry{std::string{member.event_id}, next_batch};
        ++stream.members;
        ++state_->total_members;
        while (room.size() > state_->limits.max_members_per_room)
        {
            std::ignore = room.pop_oldest();
            --stream.members;
            --state_->total_members;
        }
    }
    while (stream.rooms.size() > state_->limits.max_rooms_per_key)
    {
        auto evicted = stream.rooms.pop_oldest();
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
