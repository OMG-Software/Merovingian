// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <type_traits>
#include <utility>

namespace merovingian::core
{

// A condition variable for a value type that must stay copyable or movable, paired with
// CopyableMutex (ADR-0517). It wraps std::condition_variable, not condition_variable_any, whose
// constructor allocates under libstdc++ and would make the copy and move operations throw.
//
// Copying or moving constructs a fresh condition variable and assigning leaves this object's own
// alone. Nothing waiting on the source is moved, so copying or moving an object while a thread
// waits on it is a bug.
class CopyableConditionVariable final
{
public:
    CopyableConditionVariable() noexcept = default;
    CopyableConditionVariable(CopyableConditionVariable const& /*other*/) noexcept
    {
    }
    CopyableConditionVariable(CopyableConditionVariable&& /*other*/) noexcept
    {
    }
    auto operator=(CopyableConditionVariable const& /*other*/) noexcept -> CopyableConditionVariable&
    {
        return *this;
    }
    auto operator=(CopyableConditionVariable&& /*other*/) noexcept -> CopyableConditionVariable&
    {
        return *this;
    }
    ~CopyableConditionVariable() = default;

    auto notify_one() noexcept -> void
    {
        condition_.notify_one();
    }

    auto notify_all() noexcept -> void
    {
        condition_.notify_all();
    }

    // Waits until `predicate` is true or `deadline` passes; returns the predicate's final value.
    // `lock` must own the mutex that guards the state the predicate reads.
    template <typename Clock, typename Duration, typename Predicate>
    [[nodiscard]] auto wait_until(std::unique_lock<std::mutex>& lock,
                                  std::chrono::time_point<Clock, Duration> const& deadline, Predicate predicate) -> bool
    {
        return condition_.wait_until(lock, deadline, std::move(predicate));
    }

private:
    std::condition_variable condition_{};
};

static_assert(std::is_nothrow_default_constructible_v<CopyableConditionVariable>);
static_assert(std::is_nothrow_copy_constructible_v<CopyableConditionVariable>);
static_assert(std::is_nothrow_move_constructible_v<CopyableConditionVariable>);
static_assert(std::is_nothrow_copy_assignable_v<CopyableConditionVariable>);
static_assert(std::is_nothrow_move_assignable_v<CopyableConditionVariable>);

} // namespace merovingian::core
