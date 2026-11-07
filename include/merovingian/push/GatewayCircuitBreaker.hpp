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
