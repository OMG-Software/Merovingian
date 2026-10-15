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
    template <typename Open, typename Reusable>
    [[nodiscard]] auto acquire(Open const& open, Reusable const& reusable) -> std::optional<Lease>
    {
        auto lock = std::unique_lock{mutex_};
        available_.wait(lock, [this] {
            return in_use_ < limit_;
        });
        ++in_use_;
        while (!idle_.empty())
        {
            auto candidate = std::move(idle_.back());
            idle_.pop_back();
            lock.unlock(); // LOCK_RELEASE: reviewed — the pool's own mutex, released so the liveness check never
                           // blocks other writers; the slot is already counted in in_use_.
            if (reusable(candidate))
            {
                return Lease{*this, std::move(candidate)};
            }
            lock.lock();
        }
        lock.unlock(); // LOCK_RELEASE: reviewed — the pool's own mutex, released so opening a connection (a
                       // network round trip for PostgreSQL) never blocks other writers.
        auto opened = open();
        if (!opened.has_value())
        {
            lock.lock();
            --in_use_;
            available_.notify_one();
            return std::nullopt;
        }
        opened_.fetch_add(1U, std::memory_order_relaxed);
        return Lease{*this, std::move(*opened)};
    }

    // Connections ever opened by this pool.
    [[nodiscard]] auto opened_total() const noexcept -> std::uint64_t
    {
        return opened_.load(std::memory_order_relaxed);
    }

private:
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

    std::mutex mutex_{};
    std::condition_variable available_{};
    std::vector<Connection> idle_{};
    std::uint32_t limit_{1U};
    std::uint32_t in_use_{0U};
    std::atomic<std::uint64_t> opened_{0U};
};

} // namespace merovingian::database
