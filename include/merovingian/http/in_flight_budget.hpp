// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::http
{

// Bounds how much work may be in flight at once, both across the whole process
// and per client key (see client_address_key). Admission is decided at the
// door and never waits: over either cap `try_acquire` answers "no" at once, so
// a caller can refuse the request instead of parking a thread behind it.
//
// This is an admission guard, not a queue and not a pool. It exists for
// operations that block the calling thread on a peer this server does not
// control (ADR-0079), where the only defence is to bound how many threads such
// calls may hold. Thread-safe.
class InFlightBudget final
{
public:
    // One admitted operation. Releases its count when destroyed, on every path,
    // so no error path can leak a slot. Move-only; the budget must outlive
    // every slot it hands out.
    class Slot final
    {
    public:
        Slot(Slot const&) = delete;
        auto operator=(Slot const&) -> Slot& = delete;
        Slot(Slot&& other) noexcept;
        auto operator=(Slot&&) -> Slot& = delete;
        ~Slot();

    private:
        friend class InFlightBudget;
        Slot(InFlightBudget& budget, std::string key) noexcept;

        InFlightBudget& m_budget;
        std::string m_key;
        bool m_held{true};
    };

    // A reserved place for a request that waits for a slot (ADR-0310). A waiting request holds its thread
    // as surely as one making its call, so it counts toward the global cap together with the slots in
    // flight. Releases its place when destroyed unless it became a slot. Move-only; the budget must outlive it.
    class Waiter final
    {
    public:
        Waiter(Waiter const&) = delete;
        auto operator=(Waiter const&) -> Waiter& = delete;
        Waiter(Waiter&& other) noexcept;
        auto operator=(Waiter&&) -> Waiter& = delete;
        ~Waiter();

    private:
        friend class InFlightBudget;
        explicit Waiter(InFlightBudget& budget) noexcept;

        InFlightBudget& m_budget;
        bool m_held{true};
    };

    InFlightBudget() = default;
    InFlightBudget(InFlightBudget const&) = delete;
    auto operator=(InFlightBudget const&) -> InFlightBudget& = delete;
    InFlightBudget(InFlightBudget&&) = delete;
    auto operator=(InFlightBudget&&) -> InFlightBudget& = delete;
    ~InFlightBudget() = default;

    // A slot for `key` when fewer than `global_cap` operations are in flight
    // overall and fewer than `per_key_cap` under `key`; nullopt otherwise. A cap
    // of 0 admits nothing. The caps are passed per call so a reloaded
    // configuration takes effect on the next admission without resetting the
    // counts of operations already in flight.
    [[nodiscard]] auto try_acquire(std::string key, std::uint32_t global_cap, std::uint32_t per_key_cap)
        -> std::optional<Slot>;

    // A place to wait when the operations in flight and the requests already waiting are together fewer
    // than `global_cap`; nullopt otherwise, and the caller refuses at once (ADR-0310). try_acquire counts
    // waiters too, so a new request never takes the room a waiter holds.
    [[nodiscard]] auto try_reserve_wait(std::uint32_t global_cap) -> std::optional<Waiter>;

    // Turns `waiter` into a slot for `key` when fewer than `per_key_cap` operations are in flight under
    // `key`; nullopt otherwise, and `waiter` keeps its place. The global cap is not consulted again: the
    // population is unchanged, one waiter becoming one operation in flight.
    [[nodiscard]] auto try_acquire_waiting(Waiter& waiter, std::string key, std::uint32_t per_key_cap)
        -> std::optional<Slot>;

    // Operations currently in flight across all keys.
    [[nodiscard]] auto active() const -> std::uint32_t;

    // Requests currently holding a place to wait.
    [[nodiscard]] auto waiting() const -> std::uint32_t;

    // Operations currently in flight under `key`.
    [[nodiscard]] auto active(std::string_view key) const -> std::uint32_t;

    // Keys with at least one operation in flight. Keys are erased when their
    // count reaches zero, so memory is bounded by live operations.
    [[nodiscard]] auto tracked_keys() const -> std::size_t;

private:
    auto release(std::string const& key) noexcept -> void;
    auto release_wait() noexcept -> void;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::uint32_t> m_counts;
    std::uint32_t m_total{0U};
    std::uint32_t m_waiting{0U};
};

} // namespace merovingian::http
