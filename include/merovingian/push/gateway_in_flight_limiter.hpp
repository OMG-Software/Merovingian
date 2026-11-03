// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::push
{

// Caps how many requests are in flight to one push gateway host and to one resolved address at a
// time (F-79, ADR-0409). The global delivery budget and the per-recipient cap (ADR-0140) bound how
// many deliveries run; neither bounds how many of them wait on the same remote server, and a
// pusher's URL is chosen by its owner. A per-host breaker alone is sidestepped with many
// subdomains of one server, so the resolved address is capped as well. A request over either cap
// is refused at once, never queued, and the caller retries it later.
//
// Thread-safe. Counts live only while a Slot does, so the table holds at most the keys of the
// requests in flight: it is bounded by the delivery budget, not by the number of gateways seen.
class GatewayInFlightLimiter final
{
public:
    // One count on each of a set of keys, returned when it is destroyed.
    class Slot final
    {
    public:
        Slot() = default;
        ~Slot();
        Slot(Slot const&) = delete;
        auto operator=(Slot const&) -> Slot& = delete;
        Slot(Slot&& other) noexcept;
        auto operator=(Slot&& other) noexcept -> Slot&;

    private:
        friend class GatewayInFlightLimiter;
        Slot(GatewayInFlightLimiter& limiter, std::vector<std::string> keys);
        auto release() noexcept -> void;

        std::optional<std::reference_wrapper<GatewayInFlightLimiter>> limiter_{};
        std::vector<std::string> keys_{};
    };

    // Takes one count on every key of `keys` (a repeated key counts once) if each is below `cap`;
    // otherwise takes none and returns nullopt. A `cap` of 0 is treated as 1.
    [[nodiscard]] auto try_acquire(std::span<std::string const> keys, std::size_t cap) -> std::optional<Slot>;

    // Requests in flight on `key`.
    [[nodiscard]] auto in_flight(std::string_view key) const -> std::size_t;
    // Keys with a request in flight.
    [[nodiscard]] auto tracked_keys() const -> std::size_t;

private:
    mutable std::mutex mutex_{};
    std::unordered_map<std::string, std::size_t> counts_{};
};

} // namespace merovingian::push
