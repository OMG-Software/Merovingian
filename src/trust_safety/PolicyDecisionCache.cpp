// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/trust_safety/PolicyDecisionCache.hpp"

#include "merovingian/trust_safety/PolicyServerHook.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::trust_safety
{

PolicyDecisionCache::Leader::Leader(PolicyDecisionCache& cache, std::string key) noexcept
    : cache_{&cache}
    , key_{std::move(key)}
{
}

PolicyDecisionCache::Leader::Leader(Leader&& other) noexcept
    : cache_{std::exchange(other.cache_, nullptr)}
    , key_{std::move(other.key_)}
{
}

auto PolicyDecisionCache::Leader::operator=(Leader&& other) noexcept -> Leader&
{
    if (this != &other)
    {
        finish(std::nullopt, std::chrono::steady_clock::now());
        cache_ = std::exchange(other.cache_, nullptr);
        key_ = std::move(other.key_);
    }
    return *this;
}

PolicyDecisionCache::Leader::~Leader()
{
    finish(std::nullopt, std::chrono::steady_clock::now());
}

auto PolicyDecisionCache::Leader::publish(PolicyServerHook const& decision,
                                          std::chrono::steady_clock::time_point now) -> void
{
    finish(decision, now);
}

auto PolicyDecisionCache::Leader::finish(std::optional<PolicyServerHook> decision,
                                         std::chrono::steady_clock::time_point now) noexcept -> void
{
    if (cache_ == nullptr)
    {
        return;
    }
    auto* const cache = std::exchange(cache_, nullptr);
    cache->finish(key_, std::move(decision), now);
}

auto PolicyDecisionCache::acquire(std::string_view key, std::chrono::steady_clock::time_point now,
                                  Settings const& settings, std::chrono::milliseconds wait) -> Claim
{
    auto lock = std::unique_lock{mutex_};
    max_entries_ = std::max(settings.max_entries, std::size_t{1U});
    auto const name = std::string{key};
    auto const fresh = [&](Entry const& entry, std::chrono::steady_clock::time_point at) {
        return entry.decision.has_value() && at - entry.decided_at < settings.fresh_for;
    };
    auto const found = entries_.find(name);
    if (found != entries_.end() && fresh(found->second, now))
    {
        return {found->second.decision, std::nullopt};
    }
    if (found != entries_.end() && found->second.asking)
    {
        auto const seen = found->second.asks_ended;
        auto const deadline = std::chrono::steady_clock::now() + wait;
        ended_.wait_until(lock, deadline, [&] {
            auto const current = entries_.find(name);
            return current == entries_.end() || !current->second.asking || current->second.asks_ended != seen;
        });
        auto const current = entries_.find(name);
        if (current != entries_.end() && !current->second.asking && current->second.asks_ended != seen &&
            current->second.decision.has_value() && fresh(current->second, current->second.decided_at))
        {
            return {current->second.decision, std::nullopt};
        }
        // The request that was asking got no decision, or took too long: this one has none to use. It does not ask
        // as well, so one origin costs one place in the budget however many of its requests arrive together.
        return {};
    }
    auto& entry = entries_[name];
    entry.asking = true;
    return {std::nullopt, Leader{*this, name}};
}

auto PolicyDecisionCache::stale(std::string_view key, std::chrono::steady_clock::time_point now,
                                Settings const& settings) const -> std::optional<PolicyServerHook>
{
    auto const lock = std::lock_guard{mutex_};
    auto const found = entries_.find(std::string{key});
    if (found == entries_.end() || !found->second.decision.has_value() ||
        now - found->second.decided_at > settings.usable_stale_for)
    {
        return std::nullopt;
    }
    return found->second.decision;
}

auto PolicyDecisionCache::size() const -> std::size_t
{
    auto const lock = std::lock_guard{mutex_};
    return entries_.size();
}

auto PolicyDecisionCache::finish(std::string const& key, std::optional<PolicyServerHook> decision,
                                 std::chrono::steady_clock::time_point now) noexcept -> void
{
    try
    {
        {
            auto const lock = std::lock_guard{mutex_};
            auto const found = entries_.find(key);
            if (found != entries_.end())
            {
                found->second.asking = false;
                ++found->second.asks_ended;
                if (decision.has_value())
                {
                    found->second.decision = std::move(decision);
                    found->second.decided_at = now;
                }
                else if (!found->second.decision.has_value())
                {
                    entries_.erase(found);
                }
            }
            while (entries_.size() > max_entries_)
            {
                auto oldest = entries_.end();
                for (auto it = entries_.begin(); it != entries_.end(); ++it)
                {
                    if (!it->second.asking && (oldest == entries_.end() ||
                                               it->second.decided_at < oldest->second.decided_at))
                    {
                        oldest = it;
                    }
                }
                if (oldest == entries_.end())
                {
                    break;
                }
                entries_.erase(oldest);
            }
        }
        ended_.notify_all();
    }
    catch (...)
    {
        // Releasing a leader must not throw; a waiter times out instead.
    }
}

} // namespace merovingian::trust_safety
