// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::push
{

// OUT-3, ADR-0151: when a push gateway host cannot be reached
// `failure_threshold` times in a row (see push::gateway_circuit_outcome: a
// connection, TLS, DNS or timeout failure; never an HTTP answer such as a 5xx,
// which concerns one notification), its circuit opens and the host
// is not contacted for `cooldown`. After that, one request per cooldown window
// is let through as a probe until one succeeds. Gateway URLs are client-supplied,
// so the number of hosts tracked is bounded by `max_hosts` (the least recently
// failing host is forgotten first).
struct GatewayCircuitBreakerPolicy final
{
    std::uint32_t failure_threshold{3U};
    std::chrono::seconds cooldown{300};
    std::size_t max_hosts{4096U};
};

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
    [[nodiscard]] auto tracked_hosts() const -> std::size_t;

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
};

} // namespace merovingian::push
