// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace merovingian::database
{

// DB-7, ADR-0154: at most `limit` connections in use at once, reused between
// leases. Opening a connection happens outside the pool's lock. A lease is held
// only for one transaction, never across anything that could take another
// lease, so waiting for a free connection cannot deadlock.
template <typename Connection>
class ConnectionPool final
{
public:
    // A connection in use. It goes back to the pool when the lease ends, unless
    // discard() was called (the connection is then closed).
    class Lease final
    {
    public:
        Lease(ConnectionPool& pool, Connection connection)
            : pool_{pool}
            , connection_{std::move(connection)}
        {
        }
        Lease(Lease const&) = delete;
        auto operator=(Lease const&) -> Lease& = delete;
        Lease(Lease&& other) noexcept
            : pool_{other.pool_}
            , connection_{std::exchange(other.connection_, std::nullopt)}
            , discarded_{other.discarded_}
        {
        }
        auto operator=(Lease&&) -> Lease& = delete;
        ~Lease()
        {
            if (connection_.has_value())
            {
                pool_.get().give_back(std::move(*connection_), !discarded_);
            }
        }

        [[nodiscard]] auto get() noexcept -> Connection&
        {
            return *connection_;
        }
        auto discard() noexcept -> void
        {
            discarded_ = true;
        }

    private:
        std::reference_wrapper<ConnectionPool> pool_;
        std::optional<Connection> connection_;
        bool discarded_{false};
    };

    explicit ConnectionPool(std::uint32_t limit)
        : limit_{std::max(limit, std::uint32_t{1U})}
    {
    }
    ConnectionPool(ConnectionPool const&) = delete;
    auto operator=(ConnectionPool const&) -> ConnectionPool& = delete;
    ConnectionPool(ConnectionPool&&) = delete;
    auto operator=(ConnectionPool&&) -> ConnectionPool& = delete;
    ~ConnectionPool() = default;

    auto set_limit(std::uint32_t limit) -> void
    {
        auto const lock = std::lock_guard{mutex_};
        limit_ = std::max(limit, std::uint32_t{1U});
        while (idle_.size() > limit_)
        {
            idle_.pop_back();
        }
        available_.notify_all();
    }

    // Waits until fewer than `limit` connections are in use, then hands out an
    // idle connection that `reusable` accepts (others are closed), or one made by
    // `open` (returning std::optional<Connection>). nullopt when `open` fails.
    // The pool's mutex is never held while `open` or `reusable` runs (a network
    // round trip for PostgreSQL), so neither blocks other writers.
    template <typename Open, typename Reusable>
    [[nodiscard]] auto acquire(Open const& open, Reusable const& reusable) -> std::optional<Lease>
    {
        {
            auto lock = std::unique_lock{mutex_};
            available_.wait(lock, [this] {
                return in_use_ < limit_;
            });
            ++in_use_;
        }
        // Gives the slot back on every way out (a failed open, or `open` or
        // `reusable` throwing) unless a lease takes it over. A slot not given
        // back is lost for good: waiting for one has no timeout.
        auto reservation = SlotReservation{*this};
        while (auto candidate = take_idle())
        {
            if (reusable(*candidate))
            {
                reservation.hand_to_lease();
                return Lease{*this, std::move(*candidate)};
            }
        }
        auto opened = open();
        if (!opened.has_value())
        {
            return std::nullopt;
        }
        opened_.fetch_add(1U, std::memory_order_relaxed);
        reservation.hand_to_lease();
        return Lease{*this, std::move(*opened)};
    }

    // Connections ever opened by this pool.
    [[nodiscard]] auto opened_total() const noexcept -> std::uint64_t
    {
        return opened_.load(std::memory_order_relaxed);
    }

    // Slots held by leases and acquisitions in progress.
    [[nodiscard]] auto in_use() const -> std::uint32_t
    {
        auto const lock = std::lock_guard{mutex_};
        return in_use_;
    }

private:
    class SlotReservation final
    {
    public:
        explicit SlotReservation(ConnectionPool& pool) noexcept
            : pool_{pool}
        {
        }
        SlotReservation(SlotReservation const&) = delete;
        auto operator=(SlotReservation const&) -> SlotReservation& = delete;
        SlotReservation(SlotReservation&&) = delete;
        auto operator=(SlotReservation&&) -> SlotReservation& = delete;
        ~SlotReservation()
        {
            if (!handed_over_)
            {
                auto& pool = pool_.get();
                auto const lock = std::lock_guard{pool.mutex_};
                --pool.in_use_;
                pool.available_.notify_one();
            }
        }

        auto hand_to_lease() noexcept -> void
        {
            handed_over_ = true;
        }

    private:
        std::reference_wrapper<ConnectionPool> pool_;
        bool handed_over_{false};
    };

    // The most recently returned idle connection, taken out of the pool, or
    // nullopt when there is none.
    [[nodiscard]] auto take_idle() -> std::optional<Connection>
    {
        auto const lock = std::lock_guard{mutex_};
        if (idle_.empty())
        {
            return std::nullopt;
        }
        auto candidate = std::optional<Connection>{std::move(idle_.back())};
        idle_.pop_back();
        return candidate;
    }

    auto give_back(Connection connection, bool keep) -> void
    {
        auto const lock = std::lock_guard{mutex_};
        --in_use_;
        if (keep && idle_.size() < limit_)
        {
            idle_.push_back(std::move(connection));
        }
        available_.notify_one();
    }

    mutable std::mutex mutex_{};
    std::condition_variable available_{};
    std::vector<Connection> idle_{};
    std::uint32_t limit_{1U};
    std::uint32_t in_use_{0U};
    std::atomic<std::uint64_t> opened_{0U};
};

} // namespace merovingian::database
