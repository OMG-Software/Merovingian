// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/GatewayCircuitBreakerPolicy.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::push
{

// Shared by every push-delivery task; every member function is thread-safe. The
// policy is passed on each call so a configuration reload applies at once.
class GatewayCircuitBreaker final
{
public:
    // Whether a request to `host` may be sent now. Taking the probe of an open
    // circuit whose cooldown has passed counts as the window's one request.
    [[nodiscard]] auto allow(std::string_view host, std::chrono::steady_clock::time_point now,
                             GatewayCircuitBreakerPolicy const& policy) -> bool;
    // Records the outcome of a request to `host`. A success forgets the host.
    auto record(std::string_view host, bool success, std::chrono::steady_clock::time_point now,
                GatewayCircuitBreakerPolicy const& policy) -> void;
    // An answer that was not slow enough to count against `host` and not prompt enough to prove it (C48, ADR-0721): the
    // host's failures are forgotten, as for a success, but it stops being reachable_recently until a prompt answer.
    auto record_unproven_answer(std::string_view host) -> void;
    [[nodiscard]] auto tracked_hosts() const -> std::size_t;
    // ADR-0634: whether `host` answered promptly (`record(host, true, ...)`) within `policy.reachable_ttl` and has
    // not failed or answered slowly since. A host this server has never reached is not reachable: its deliveries
    // may use only the share of the delivery budget that is not reserved for hosts that are.
    [[nodiscard]] auto reachable_recently(std::string_view host, std::chrono::steady_clock::time_point now,
                                          GatewayCircuitBreakerPolicy const& policy) const -> bool;

private:
    struct HostState final
    {
        std::uint32_t consecutive_failures{0U};
        bool open{false};
        std::chrono::steady_clock::time_point open_until{};
        std::chrono::steady_clock::time_point last_failure{};
    };

    mutable std::mutex mutex_{};
    std::unordered_map<std::string, HostState> hosts_{};
    // Hosts that answered promptly, and when. Bounded by `max_hosts`, the oldest forgotten first.
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> reachable_{};
};

} // namespace merovingian::push
