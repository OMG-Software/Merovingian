// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/failure_window_table.hpp"

#include "merovingian/crypto/generic_hash.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace merovingian::auth
{

auto make_failure_key(std::string_view kind, std::string_view account, std::string_view qualifier)
    -> std::optional<FailureKey>
{
    auto const account_length = std::to_string(account.size());
    auto const pieces = std::array<std::string_view, 4U>{kind, account_length, account, qualifier};
    auto const digest = crypto::generic_hash_bytes(pieces);
    auto key = FailureKey{};
    if (!digest.has_value() || digest->size() != key.digest.size())
    {
        return std::nullopt;
    }
    std::ranges::copy(*digest, key.digest.begin());
    return key;
}

auto FailureWindowTable::KeyHash::operator()(FailureKey const& key) const noexcept -> std::size_t
{
    // The digest is uniformly distributed, so any eight bytes of it are a hash.
    auto value = std::size_t{0U};
    std::memcpy(&value, key.digest.data(), sizeof(value));
    return value;
}

FailureWindowTable::FailureWindowTable(std::size_t capacity) noexcept
    : capacity_{std::max<std::size_t>(capacity, 1U)}
{
}

auto FailureWindowTable::expire(Clock::time_point now, Clock::duration window) -> void
{
    while (!order_.empty() && now - order_.front().window_start >= window)
    {
        index_.erase(order_.front().key);
        order_.pop_front();
    }
}

auto FailureWindowTable::lockout_remaining(FailureKey const& key, Clock::time_point now, Clock::duration window,
                                           std::uint32_t threshold) -> Clock::duration
{
    expire(now, window);
    auto const found = index_.find(key);
    if (found == index_.end() || found->second->count < threshold)
    {
        return Clock::duration::zero();
    }
    return found->second->window_start + window - now;
}

auto FailureWindowTable::record_failure(FailureKey const& key, Clock::time_point now, Clock::duration window,
                                        std::uint32_t threshold) -> void
{
    expire(now, window);
    auto const found = index_.find(key);
    if (found == index_.end())
    {
        if (order_.size() >= capacity_)
        {
            index_.erase(order_.front().key);
            order_.pop_front();
        }
        order_.push_back(Entry{key, 1U, now});
        index_.emplace(key, std::prev(order_.end()));
        return;
    }

    auto& entry = *found->second;
    if (entry.count == std::numeric_limits<std::uint32_t>::max())
    {
        return;
    }
    ++entry.count;
    if (entry.count == threshold)
    {
        // Tripped: refuse for a full window from this failure. The entry moves to
        // the back so the list stays ordered by window start.
        entry.window_start = now;
        order_.splice(order_.end(), order_, found->second);
    }
}

auto FailureWindowTable::clear(FailureKey const& key) -> void
{
    auto const found = index_.find(key);
    if (found == index_.end())
    {
        return;
    }
    order_.erase(found->second);
    index_.erase(found);
}

auto FailureWindowTable::failures(FailureKey const& key, Clock::time_point now, Clock::duration window) -> std::uint32_t
{
    expire(now, window);
    auto const found = index_.find(key);
    return found == index_.end() ? 0U : found->second->count;
}

auto FailureWindowTable::size() const noexcept -> std::size_t
{
    return order_.size();
}

auto FailureWindowTable::capacity() const noexcept -> std::size_t
{
    return capacity_;
}

} // namespace merovingian::auth
