// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>

namespace merovingian::observability
{

// AUTH-1 (security-audit-report-2026-09-29.md), ADR-0080.
//
// Some audit events are triggered by requests from anyone, with no credential:
// an unknown or invalid access token, a request the rate limiter refused, or a
// request refused before it was routed. One durable audit row per such request
// hands an unauthenticated client an unbounded, synchronous database write on
// every packet it sends. The gate admits at most `audit_rate_gate_max_rows`
// durable rows per event kind per `audit_rate_gate_window`; further events in
// the window are only counted. The count is handed back with the next row the
// kind is allowed to write, so the audit trail records that events were dropped
// and how many.
inline constexpr auto audit_rate_gate_max_rows = std::uint32_t{10U};
inline constexpr auto audit_rate_gate_window = std::chrono::seconds{60};

// True for the audit event kinds the gate governs. Every other kind, including
// login successes and failures, admin actions and authenticated security
// events, is written on every occurrence.
[[nodiscard]] auto audit_event_is_rate_capped(std::string_view event_type) noexcept -> bool;

struct AuditRateDecision final
{
    // False when the event must not be written durably; it has been counted.
    bool write{true};
    // Number of events the kind suppressed since its last written row. Non-zero
    // only on the first row written after a window that overran its allowance.
    std::uint64_t suppressed{0U};
};

// Not thread-safe: the caller serialises access. The runtime appends audit rows
// under `HomeserverRuntime::mutex`, and the gate lives beside the rows it gates.
class AuditRateGate final
{
public:
    using Clock = std::chrono::steady_clock;
    using NowFn = std::function<Clock::time_point()>;

    // Decides using the gate's clock (the steady clock unless `set_clock` was called).
    [[nodiscard]] auto admit(std::string_view event_type) -> AuditRateDecision;
    // Decides for an explicit instant. Kinds outside the capped set are always
    // admitted and leave no state, so the gate's memory is bounded by the fixed
    // set of capped kinds however many distinct strings a caller offers.
    [[nodiscard]] auto admit(std::string_view event_type, Clock::time_point now) -> AuditRateDecision;

    // Replaces the clock. Test seam: production leaves the steady clock in place.
    auto set_clock(NowFn clock) -> void;

    // Number of kinds the gate currently holds state for.
    [[nodiscard]] auto tracked_kinds() const noexcept -> std::size_t;

private:
    struct Window final
    {
        Clock::time_point started{};
        std::uint32_t written{0U};
        std::uint64_t suppressed{0U};
    };

    std::map<std::string, Window, std::less<>> windows_{};
    NowFn clock_{};
};

} // namespace merovingian::observability
