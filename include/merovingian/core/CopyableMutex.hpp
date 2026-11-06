// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <mutex>
#include <type_traits>

namespace merovingian::core
{

// A mutex for a value type that must stay copyable or movable while guarding some of its members.
// A std::mutex can be neither copied nor moved, so a type that holds one would lose both; holding
// it behind a pointer allocates and leaves a moved-from object with none (ADR-0517).
//
// The lock state is never transferred. Copying or moving constructs a fresh, unlocked mutex, and
// assigning leaves this object's own mutex alone. Copying or moving an object while its mutex is
// held is a bug: the copy is not protected by the lock the source holds.
class CopyableMutex final
{
public:
    CopyableMutex() noexcept = default;
    CopyableMutex(CopyableMutex const& /*other*/) noexcept
    {
    }
    CopyableMutex(CopyableMutex&& /*other*/) noexcept
    {
    }
    auto operator=(CopyableMutex const& /*other*/) noexcept -> CopyableMutex&
    {
        return *this;
    }
    auto operator=(CopyableMutex&& /*other*/) noexcept -> CopyableMutex&
    {
        return *this;
    }
    ~CopyableMutex() = default;

    // Locks the mutex and returns the lock that owns it. The caller keeps the lock for as long as
    // the guarded members are in use.
    [[nodiscard]] auto acquire() const -> std::unique_lock<std::mutex>
    {
        return std::unique_lock<std::mutex>{mutex_};
    }

private:
    mutable std::mutex mutex_{};
};

static_assert(std::is_nothrow_default_constructible_v<CopyableMutex>);
static_assert(std::is_nothrow_copy_constructible_v<CopyableMutex>);
static_assert(std::is_nothrow_move_constructible_v<CopyableMutex>);
static_assert(std::is_nothrow_copy_assignable_v<CopyableMutex>);
static_assert(std::is_nothrow_move_assignable_v<CopyableMutex>);

} // namespace merovingian::core
