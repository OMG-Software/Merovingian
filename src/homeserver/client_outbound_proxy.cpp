// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/client_outbound_proxy.hpp"

#include "merovingian/homeserver/runtime.hpp"

#include <algorithm>
#include <utility>

namespace merovingian::homeserver
{

auto admit_client_outbound_proxy(HomeserverRuntime& runtime,
                                 std::string client_key) -> std::optional<http::InFlightBudget::Slot>
{
    auto const& policy = runtime.client_outbound_proxy_policy;
    return runtime.client_outbound_budget->try_acquire(std::move(client_key), policy.global_cap, policy.per_client_cap);
}

auto effective_client_outbound_deadline(HomeserverRuntime const& runtime,
                                        std::uint32_t requested_seconds) -> std::uint32_t
{
    // 0 means "not configured" for remote_timeout_seconds (see
    // perform_sync_outbound_call), so it never lowers the deadline.
    auto const configured = runtime.federation.config.remote_timeout_seconds;
    return configured > 0U ? std::min(requested_seconds, configured) : requested_seconds;
}

} // namespace merovingian::homeserver
