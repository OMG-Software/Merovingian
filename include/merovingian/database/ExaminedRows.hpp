// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <cstdint>

namespace merovingian::database
{

// A count of rows a read examined. Readers hold the store only by const reference, so it is mutable in the
// store, and relaxed atomic so that two readers sharing the store cannot race on it. A test reads the
// difference across an operation to prove how many rows it looked at, never how long it took.
class ExaminedRows final
{
public:
    ExaminedRows() noexcept = default;
    ExaminedRows(ExaminedRows const& other) noexcept
        : count_{other.count_.load(std::memory_order_relaxed)}
    {
    }
    auto operator=(ExaminedRows const& other) noexcept -> ExaminedRows&
    {
        count_.store(other.count_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }
    auto add(std::uint64_t rows) const noexcept -> void
    {
        count_.fetch_add(rows, std::memory_order_relaxed);
    }
    [[nodiscard]] auto value() const noexcept -> std::uint64_t
    {
        return count_.load(std::memory_order_relaxed);
    }

private:
    mutable std::atomic<std::uint64_t> count_{0U};
};

} // namespace merovingian::database
