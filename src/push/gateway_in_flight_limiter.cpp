// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/gateway_in_flight_limiter.hpp"

#include <algorithm>
#include <utility>

namespace merovingian::push
{

GatewayInFlightLimiter::Slot::Slot(GatewayInFlightLimiter& limiter, std::vector<std::string> keys)
    : limiter_{limiter}
    , keys_{std::move(keys)}
{
}

GatewayInFlightLimiter::Slot::~Slot()
{
    release();
}

GatewayInFlightLimiter::Slot::Slot(Slot&& other) noexcept
    : limiter_{std::exchange(other.limiter_, std::nullopt)}
    , keys_{std::move(other.keys_)}
{
    other.keys_.clear();
}

auto GatewayInFlightLimiter::Slot::operator=(Slot&& other) noexcept -> Slot&
{
    if (this != &other)
    {
        release();
        limiter_ = std::exchange(other.limiter_, std::nullopt);
        keys_ = std::move(other.keys_);
        other.keys_.clear();
    }
    return *this;
}

auto GatewayInFlightLimiter::Slot::release() noexcept -> void
{
    if (!limiter_.has_value())
    {
        return;
    }
    auto& limiter = limiter_->get();
    limiter_.reset();
    auto const guard = std::lock_guard{limiter.mutex_};
    for (auto const& key : keys_)
    {
        auto const found = limiter.counts_.find(key);
        if (found == limiter.counts_.end())
        {
            continue;
        }
        if (found->second <= 1U)
        {
            limiter.counts_.erase(found);
        }
        else
        {
            --found->second;
        }
    }
    keys_.clear();
}

auto GatewayInFlightLimiter::try_acquire(std::span<std::string const> keys, std::size_t cap) -> std::optional<Slot>
{
    auto distinct = std::vector<std::string>{keys.begin(), keys.end()};
    std::ranges::sort(distinct);
    auto const duplicates = std::ranges::unique(distinct);
    distinct.erase(duplicates.begin(), duplicates.end());
    auto const limit = std::max(cap, std::size_t{1U});

    auto const guard = std::lock_guard{mutex_};
    for (auto const& key : distinct)
    {
        auto const found = counts_.find(key);
        if (found != counts_.end() && found->second >= limit)
        {
            return std::nullopt;
        }
    }
    for (auto const& key : distinct)
    {
        ++counts_[key];
    }
    return Slot{*this, std::move(distinct)};
}

auto GatewayInFlightLimiter::in_flight(std::string_view key) const -> std::size_t
{
    auto const guard = std::lock_guard{mutex_};
    auto const found = counts_.find(std::string{key});
    return found == counts_.end() ? std::size_t{0U} : found->second;
}

auto GatewayInFlightLimiter::tracked_keys() const -> std::size_t
{
    auto const guard = std::lock_guard{mutex_};
    return counts_.size();
}

} // namespace merovingian::push
