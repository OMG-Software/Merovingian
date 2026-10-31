// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/http/in_flight_budget.hpp"

#include <utility>

namespace merovingian::http
{

InFlightBudget::Slot::Slot(InFlightBudget& budget, std::string key) noexcept
    : m_budget{budget}
    , m_key{std::move(key)}
{
}

InFlightBudget::Slot::Slot(Slot&& other) noexcept
    : m_budget{other.m_budget}
    , m_key{std::move(other.m_key)}
    , m_held{std::exchange(other.m_held, false)}
{
}

InFlightBudget::Slot::~Slot()
{
    if (m_held)
    {
        m_budget.release(m_key);
    }
}

InFlightBudget::Waiter::Waiter(InFlightBudget& budget) noexcept
    : m_budget{budget}
{
}

InFlightBudget::Waiter::Waiter(Waiter&& other) noexcept
    : m_budget{other.m_budget}
    , m_held{std::exchange(other.m_held, false)}
{
}

InFlightBudget::Waiter::~Waiter()
{
    if (m_held)
    {
        m_budget.release_wait();
    }
}

auto InFlightBudget::try_acquire(std::string key, std::uint32_t global_cap, std::uint32_t per_key_cap)
    -> std::optional<Slot>
{
    auto const lock = std::lock_guard{m_mutex};
    // Waiters hold threads too (ADR-0310): the room they hold is not free.
    if (m_total + m_waiting >= global_cap)
    {
        return std::nullopt;
    }
    auto const existing = m_counts.find(key);
    auto const held_by_key = existing == m_counts.end() ? 0U : existing->second;
    if (held_by_key >= per_key_cap)
    {
        return std::nullopt;
    }
    ++m_counts[key];
    ++m_total;
    return Slot{*this, std::move(key)};
}

auto InFlightBudget::try_reserve_wait(std::uint32_t global_cap) -> std::optional<Waiter>
{
    auto const lock = std::lock_guard{m_mutex};
    if (m_total + m_waiting >= global_cap)
    {
        return std::nullopt;
    }
    ++m_waiting;
    return Waiter{*this};
}

auto InFlightBudget::try_acquire_waiting(Waiter& waiter, std::string key, std::uint32_t per_key_cap)
    -> std::optional<Slot>
{
    auto const lock = std::lock_guard{m_mutex};
    if (!waiter.m_held)
    {
        return std::nullopt;
    }
    auto const existing = m_counts.find(key);
    auto const held_by_key = existing == m_counts.end() ? 0U : existing->second;
    if (held_by_key >= per_key_cap)
    {
        return std::nullopt;
    }
    // The waiter's place becomes the operation's: the population under the global cap is unchanged.
    waiter.m_held = false;
    --m_waiting;
    ++m_counts[key];
    ++m_total;
    return Slot{*this, std::move(key)};
}

auto InFlightBudget::waiting() const -> std::uint32_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_waiting;
}

auto InFlightBudget::release_wait() noexcept -> void
{
    auto const lock = std::lock_guard{m_mutex};
    if (m_waiting > 0U)
    {
        --m_waiting;
    }
}

auto InFlightBudget::active() const -> std::uint32_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_total;
}

auto InFlightBudget::active(std::string_view key) const -> std::uint32_t
{
    auto const lock = std::lock_guard{m_mutex};
    auto const it = m_counts.find(std::string{key});
    return it == m_counts.end() ? 0U : it->second;
}

auto InFlightBudget::tracked_keys() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_counts.size();
}

auto InFlightBudget::release(std::string const& key) noexcept -> void
{
    auto const lock = std::lock_guard{m_mutex};
    auto const it = m_counts.find(key);
    if (it == m_counts.end())
    {
        return;
    }
    if (m_total > 0U)
    {
        --m_total;
    }
    if (it->second <= 1U)
    {
        m_counts.erase(it);
        return;
    }
    --it->second;
}

} // namespace merovingian::http
