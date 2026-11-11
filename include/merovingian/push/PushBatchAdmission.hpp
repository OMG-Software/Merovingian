// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/GatewayInFlightLimiter.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace merovingian::push
{

// Why a recipient's batch of push deliveries was not admitted (ADR-0634).
enum class PushBatchRefusal
{
    none,
    // The batch's hosts are not all known to be reachable, and the share of the budget they may use is spent.
    unproven_share,
    // The whole budget is spent.
    global_cap,
    // One of the batch's gateway hosts already carries its share of the batches in flight.
    gateway_host,
};

// The decision to start one recipient's batch of deliveries, given how many batches are in flight (ADR-0634). The
// budget `max_in_flight_deliveries` is shared by every recipient and every gateway, and a pusher's URL is chosen by
// its owner, so no set of gateways or recipients may hold all of it: a quarter is kept for batches whose gateway
// hosts have all answered promptly lately, and each host may carry an eighth of the budget while its batches run.
// A batch over either limit is refused at once, never queued (ADR-0028).
//
// Thread-safe. The caller supplies the count of batches in flight and increments it itself; this object keeps only
// the per-host counts, which live only while an admitted batch's slot does.
class PushBatchAdmission final
{
public:
    struct Outcome final
    {
        // Held for as long as the batch runs; destroying it returns the hosts' counts.
        std::optional<GatewayInFlightLimiter::Slot> slot{};
        PushBatchRefusal refusal{PushBatchRefusal::none};
    };

    // Batches in flight at or above which a batch is refused: all of the budget for a batch whose hosts are all
    // reachable, and what is left after the reserved quarter for any other. Budgets under 4 reserve nothing.
    [[nodiscard]] static auto global_cap(std::size_t max_in_flight, bool all_hosts_reachable) noexcept -> std::size_t;
    // Batches in flight at which one gateway host is refused: an eighth of the budget, at least one.
    [[nodiscard]] static auto host_cap(std::size_t max_in_flight) noexcept -> std::size_t;

    // Admits a batch whose pushers are served by `hosts` when `in_flight` batches already run.
    [[nodiscard]] auto admit(std::size_t in_flight, std::size_t max_in_flight, std::span<std::string const> hosts,
                             bool all_hosts_reachable) -> Outcome;

    [[nodiscard]] auto host_in_flight(std::string const& host) const -> std::size_t;

private:
    GatewayInFlightLimiter hosts_{};
};

} // namespace merovingian::push
