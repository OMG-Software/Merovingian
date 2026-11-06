// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct FederationRateLimitBucket final
{
    std::string origin{};
    std::uint32_t transactions_seen{0U};
    std::uint32_t pdus_seen{0U};
    std::uint32_t edus_seen{0U};
    // Non-/send requests seen from this origin (query, backfill, membership,
    // key and state endpoints). /send traffic is counted by the three
    // weighted counters above instead, so a transaction and its contents are
    // never double-counted.
    std::uint32_t requests_seen{0U};
    std::chrono::steady_clock::time_point transaction_window_start{};
    std::chrono::steady_clock::time_point pdu_window_start{};
    std::chrono::steady_clock::time_point edu_window_start{};
    std::chrono::steady_clock::time_point request_window_start{};
};

} // namespace merovingian::federation
