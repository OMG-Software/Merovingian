// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/PushBatchAdmission.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <utility>

namespace merovingian::push
{

auto PushBatchAdmission::global_cap(std::size_t max_in_flight, bool all_hosts_reachable) noexcept -> std::size_t
{
    if (all_hosts_reachable || max_in_flight < 4U)
    {
        return max_in_flight;
    }
    return max_in_flight - (max_in_flight / 4U);
}

auto PushBatchAdmission::host_cap(std::size_t max_in_flight) noexcept -> std::size_t
{
    return std::max(std::size_t{1U}, max_in_flight / 8U);
}

auto PushBatchAdmission::admit(std::size_t in_flight, std::size_t max_in_flight, std::span<std::string const> hosts,
                               bool all_hosts_reachable) -> Outcome
{
    if (in_flight >= max_in_flight)
    {
        return {std::nullopt, PushBatchRefusal::global_cap};
    }
    if (in_flight >= global_cap(max_in_flight, all_hosts_reachable))
    {
        return {std::nullopt, PushBatchRefusal::unproven_share};
    }
    auto slot = hosts_.try_acquire(hosts, host_cap(max_in_flight));
    if (!slot.has_value())
    {
        return {std::nullopt, PushBatchRefusal::gateway_host};
    }
    return {std::move(slot), PushBatchRefusal::none};
}

auto PushBatchAdmission::host_in_flight(std::string const& host) const -> std::size_t
{
    return hosts_.in_flight(host);
}

} // namespace merovingian::push
