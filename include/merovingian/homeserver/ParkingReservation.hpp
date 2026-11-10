// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace merovingian::homeserver
{

// A counted slot in one of the dispatcher's parking budgets (kept-alive
// connections between requests; new connections before their first
// request). The counter is shared so a reservation may outlive the
// dispatcher that issued it.
class ParkingReservation final
{
public:
    using Counter = std::shared_ptr<std::atomic<std::uint32_t>>; // SHARED_PTR: reviewed — outlives the dispatcher

    ParkingReservation(ParkingReservation const&) = delete;
    auto operator=(ParkingReservation const&) -> ParkingReservation& = delete;
    ParkingReservation(ParkingReservation&& other) noexcept
        : m_counter{std::move(other.m_counter)}
    {
    }
    auto operator=(ParkingReservation&& other) noexcept -> ParkingReservation&
    {
        if (this != &other)
        {
            release();
            m_counter = std::move(other.m_counter);
        }
        return *this;
    }
    ~ParkingReservation()
    {
        release();
    }

    // A slot when fewer than `cap` are held; nullopt at the cap. A cap of
    // 0 means unbounded.
    [[nodiscard]] static auto try_acquire(Counter const& counter, std::uint32_t cap)
        -> std::optional<ParkingReservation>
    {
        auto current = counter->load(std::memory_order_relaxed);
        while (cap == 0U || current < cap)
        {
            if (counter->compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                               std::memory_order_relaxed))
            {
                return ParkingReservation{counter};
            }
        }
        return std::nullopt;
    }

private:
    explicit ParkingReservation(Counter counter) noexcept
        : m_counter{std::move(counter)}
    {
    }
    auto release() noexcept -> void
    {
        if (m_counter != nullptr)
        {
            m_counter->fetch_sub(1U, std::memory_order_relaxed);
            m_counter = nullptr;
        }
    }

    Counter m_counter{};
};

} // namespace merovingian::homeserver
