// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/GatewayCircuitBreaker.hpp"

#include "merovingian/push/GatewayCircuitBreakerPolicy.hpp"

#include <algorithm>
#include <string>
#include <tuple>

namespace merovingian::push
{

auto GatewayCircuitBreaker::allow(std::string_view host, std::chrono::steady_clock::time_point now,
                                  GatewayCircuitBreakerPolicy const& policy) -> bool
{
    auto const lock = std::lock_guard{mutex_};
    auto const found = hosts_.find(std::string{host});
    if (found == hosts_.end() || !found->second.open)
    {
        return true;
    }
    if (now < found->second.open_until)
    {
        return false;
    }
    // The cooldown has passed: this request is the window's one probe. The
    // next is allowed only after another cooldown, so a probe that never
    // reports back cannot hold the host shut for ever.
    found->second.open_until = now + policy.cooldown;
    return true;
}

auto GatewayCircuitBreaker::record(std::string_view host, bool success, std::chrono::steady_clock::time_point now,
                                   GatewayCircuitBreakerPolicy const& policy) -> void
{
    auto const lock = std::lock_guard{mutex_};
    auto const key = std::string{host};
    if (success)
    {
        std::ignore = hosts_.erase(key);
        if (!reachable_.contains(key) && policy.max_hosts > 0U)
        {
            while (reachable_.size() >= policy.max_hosts)
            {
                auto const oldest = std::ranges::min_element(reachable_, {}, [](auto const& entry) {
                    return entry.second;
                });
                if (oldest == reachable_.end())
                {
                    break;
                }
                reachable_.erase(oldest);
            }
        }
        reachable_[key] = now;
        return;
    }
    std::ignore = reachable_.erase(key);
    if (!hosts_.contains(key) && policy.max_hosts > 0U)
    {
        while (hosts_.size() >= policy.max_hosts)
        {
            auto const oldest = std::ranges::min_element(hosts_, {}, [](auto const& entry) {
                return entry.second.last_failure;
            });
            // Not reachable while the map is non-empty; stated so that gcc's
            // flow analysis (-Wnull-dereference, Fedora/RHEL -O2) can see the
            // iterator is valid.
            if (oldest == hosts_.end())
            {
                break;
            }
            hosts_.erase(oldest);
        }
    }
    auto& state = hosts_[key];
    ++state.consecutive_failures;
    state.last_failure = now;
    if (state.consecutive_failures >= std::max(policy.failure_threshold, std::uint32_t{1U}))
    {
        state.open = true;
        state.open_until = now + policy.cooldown;
    }
}

auto GatewayCircuitBreaker::record_unproven_answer(std::string_view host) -> void
{
    auto const lock = std::lock_guard{mutex_};
    auto const key = std::string{host};
    std::ignore = hosts_.erase(key);
    std::ignore = reachable_.erase(key);
}

auto GatewayCircuitBreaker::reachable_recently(std::string_view host, std::chrono::steady_clock::time_point now,
                                               GatewayCircuitBreakerPolicy const& policy) const -> bool
{
    auto const lock = std::lock_guard{mutex_};
    auto const found = reachable_.find(std::string{host});
    return found != reachable_.end() && now - found->second <= policy.reachable_ttl;
}

auto GatewayCircuitBreaker::tracked_hosts() const -> std::size_t
{
    auto const lock = std::lock_guard{mutex_};
    return hosts_.size();
}

} // namespace merovingian::push
