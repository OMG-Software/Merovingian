// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ParkedPollRegistry.hpp"

namespace merovingian::sync
{

ParkedPollRegistry::~ParkedPollRegistry() = default;

auto ParkedPollRegistry::start(ParkedPollLimits, ResumeFn) -> bool
{
    return false;
}

auto ParkedPollRegistry::request_stop() -> void
{
}

auto ParkedPollRegistry::running() const -> bool
{
    return m_started && !m_stopping && m_next_ticket == 0U;
}

auto ParkedPollRegistry::park(std::string_view, std::chrono::steady_clock::time_point, std::unique_ptr<ParkedPoll>&)
    -> ParkOutcome
{
    return ParkOutcome{false, 0U, "not implemented"};
}

auto ParkedPollRegistry::wake_users(std::span<std::string const>) -> void
{
}

auto ParkedPollRegistry::wake_all() -> void
{
}

auto ParkedPollRegistry::wake(std::uint64_t) -> void
{
}

auto ParkedPollRegistry::parked() const -> std::size_t
{
    return 0U;
}

auto ParkedPollRegistry::parked_for(std::string_view) const -> std::size_t
{
    return 0U;
}

auto ParkedPollRegistry::run() -> void
{
}

auto ParkedPollRegistry::make_ready_locked(std::unordered_map<std::uint64_t, Entry>::iterator, WakeReason) -> void
{
}

} // namespace merovingian::sync
