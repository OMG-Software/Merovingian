// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/PolicyServerHook.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::trust_safety
{

// The policy server's decision about one inbound federation origin, remembered for a short time and asked for by one
// request at a time (ADR-0635). The question sent to the policy server is the surface and the origin and nothing
// else, so its answer is a function of the origin alone; asking again for every request made the ask rate equal the
// request rate and let any peer that kept the shared budget busy choose the outcome for the others.
//
// A decision is kept only when the policy server really gave one. A failure to get one (unreachable, refused,
// unparseable, no place in the budget) is never kept, so `policy_server_allow_without_result` keeps deciding it.
//
// Thread-safe. The caller must not hold the runtime lock across `acquire`, which can wait for another request's ask.
class PolicyDecisionCache final
{
public:
    struct Settings final
    {
        // A decision this young is used without asking.
        std::chrono::milliseconds fresh_for{30'000};
        // A decision this young is used when the budget has no place left for an ask (never for any other failure).
        std::chrono::milliseconds usable_stale_for{600'000};
        // Origins remembered; the oldest decision is forgotten first. Origins being asked about are never forgotten.
        std::size_t max_entries{1024U};
    };

    // Held by the one request asking the policy server about an origin. `publish` stores its decision; a leader
    // destroyed without publishing records a failure, so no waiting request is left waiting.
    class Leader final
    {
    public:
        Leader() = default;
        Leader(Leader const&) = delete;
        auto operator=(Leader const&) -> Leader& = delete;
        Leader(Leader&& other) noexcept;
        auto operator=(Leader&& other) noexcept -> Leader&;
        ~Leader();

        // Stores `decision` (a hook with `decision_received` set) and wakes the requests waiting on it.
        auto publish(PolicyServerHook const& decision, std::chrono::steady_clock::time_point now) -> void;

    private:
        friend class PolicyDecisionCache;
        Leader(PolicyDecisionCache& cache, std::string key) noexcept;
        auto finish(std::optional<PolicyServerHook> decision, std::chrono::steady_clock::time_point now) noexcept
            -> void;

        PolicyDecisionCache* cache_{nullptr};
        std::string key_{};
    };

    struct Claim final
    {
        // A decision to use: fresh, or the one a request that was already asking has just stored.
        std::optional<PolicyServerHook> decision{};
        // Set when this request is the one to ask.
        std::optional<Leader> leader{};
    };

    // A fresh decision for `key`; otherwise, if another request is asking, waits up to `wait` for it and returns what
    // it stored (no decision if it failed); otherwise makes this request the leader.
    [[nodiscard]] auto acquire(std::string_view key, std::chrono::steady_clock::time_point now,
                               Settings const& settings, std::chrono::milliseconds wait) -> Claim;

    // A decision for `key` no older than `settings.usable_stale_for`, for use when no place is left in the budget.
    [[nodiscard]] auto stale(std::string_view key, std::chrono::steady_clock::time_point now,
                             Settings const& settings) const -> std::optional<PolicyServerHook>;

    [[nodiscard]] auto size() const -> std::size_t;

private:
    struct Entry final
    {
        std::optional<PolicyServerHook> decision{};
        std::chrono::steady_clock::time_point decided_at{};
        bool asking{false};
        // Bumped each time an ask ends, so a waiter can tell its leader's end from a later one.
        std::uint64_t asks_ended{0U};
    };

    auto finish(std::string const& key, std::optional<PolicyServerHook> decision,
                std::chrono::steady_clock::time_point now) noexcept -> void;

    mutable std::mutex mutex_{};
    std::condition_variable ended_{};
    std::unordered_map<std::string, Entry> entries_{};
    std::size_t max_entries_{1024U};
};

} // namespace merovingian::trust_safety
