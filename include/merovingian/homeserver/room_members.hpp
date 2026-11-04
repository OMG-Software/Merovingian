// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <functional>
#include <initializer_list>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// The joined members of a local room: the ordered list (joining order, iterated by the code that fans out to the
// members and handed to the appservice module as a `std::vector<std::string> const&`) and a hash set of the same
// members, so "is this user a member" is one lookup rather than a scan (ADR-0496).
//
// Every write goes through `add` or `remove`, which keep the two in step; the list is exposed read-only, so a write
// that skips the set does not compile. Callers hold `runtime.mutex`, as for the rest of `LocalDatabase`.
class RoomMembers final
{
public:
    using value_type = std::string;
    using const_iterator = std::vector<std::string>::const_iterator;

    RoomMembers() = default;

    // A member named twice is a member once, in the position of its first mention.
    RoomMembers(std::initializer_list<std::string> members)
    {
        for (auto const& member : members)
        {
            std::ignore = add(member);
        }
    }

    // NOLINTNEXTLINE(google-explicit-constructor): a roster built as a vector converts, as the vector did.
    RoomMembers(std::vector<std::string> members)
    {
        for (auto& member : members)
        {
            std::ignore = add(std::move(member));
        }
    }

    // Adds `user_id` unless it is already a member; returns whether it was added.
    auto add(std::string user_id) -> bool
    {
        if (!set_.insert(user_id).second)
        {
            return false;
        }
        list_.push_back(std::move(user_id));
        return true;
    }

    // `add` under the names the call sites that held a vector use.
    auto push_back(std::string user_id) -> bool
    {
        return add(std::move(user_id));
    }
    auto emplace_back(std::string user_id) -> bool
    {
        return add(std::move(user_id));
    }

    // Removes `user_id`, keeping the order of the rest; returns whether it was a member.
    auto remove(std::string_view user_id) -> bool
    {
        auto const found = set_.find(user_id);
        if (found == set_.end())
        {
            return false;
        }
        set_.erase(found);
        for (auto it = list_.begin(); it != list_.end(); ++it)
        {
            if (*it == user_id)
            {
                list_.erase(it);
                break;
            }
        }
        return true;
    }

    // Removes every member (a roster rebuilt from scratch, a test).
    auto clear() noexcept -> void
    {
        list_.clear();
        set_.clear();
    }

    [[nodiscard]] auto contains(std::string_view user_id) const -> bool
    {
        return set_.contains(user_id);
    }

    [[nodiscard]] auto values() const noexcept -> std::vector<std::string> const&
    {
        return list_;
    }
    // NOLINTNEXTLINE(google-explicit-constructor): a read-only view where a `std::vector<std::string> const&` is taken.
    operator std::vector<std::string> const&() const noexcept
    {
        return list_;
    }

    [[nodiscard]] auto begin() const noexcept -> const_iterator
    {
        return list_.begin();
    }
    [[nodiscard]] auto end() const noexcept -> const_iterator
    {
        return list_.end();
    }
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return list_.size();
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return list_.empty();
    }
    [[nodiscard]] auto front() const -> std::string const&
    {
        return list_.front();
    }
    [[nodiscard]] auto back() const -> std::string const&
    {
        return list_.back();
    }
    [[nodiscard]] auto operator[](std::size_t position) const -> std::string const&
    {
        return list_[position];
    }

private:
    // Looks a string_view up without making a string.
    struct IdHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view id) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(id);
        }
    };

    std::vector<std::string> list_{};
    std::unordered_set<std::string, IdHash, std::equal_to<>> set_{};
};

} // namespace merovingian::homeserver
