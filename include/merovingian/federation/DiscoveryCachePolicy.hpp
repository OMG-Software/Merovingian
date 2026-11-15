// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::federation
{

// Which cached results a lookup may be answered from.
enum class DiscoveryCachePolicy
{
    // Any fresh entry, a remembered failure included: for callers that can
    // afford to refuse a destination for the cache lifetime (key resolution,
    // appservice and push delivery, where a failure is retried by the queue).
    remember_failures,
    // A fresh success only. A remembered failure is ignored and the network
    // asked again, so a client's retry after the destination recovers is not
    // refused for the rest of the lifetime: the federated join and the other
    // outbound calls a client request triggers, and outbound delivery, which
    // its own backoff paces (ADR-0749).
    successes_only,
};

} // namespace merovingian::federation
