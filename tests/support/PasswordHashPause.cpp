// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "PasswordHashPause.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace
{

struct PauseState
{
    std::mutex mutex;
    std::condition_variable changed;
    bool armed{false};
    bool hashing{false};
    bool released{false};
};

// A function-local static, so a constructor that might throw is not run at namespace scope (cert-err58-cpp).
auto pause_state() -> PauseState&
{
    static auto state = PauseState{};
    return state;
}

} // namespace

namespace merovingian::tests
{

PasswordHashPause::PasswordHashPause() noexcept
{
    auto& state = pause_state();
    auto const lock = std::scoped_lock{state.mutex};
    state.armed = true;
    state.hashing = false;
    state.released = false;
}

PasswordHashPause::~PasswordHashPause()
{
    auto& state = pause_state();
    {
        auto const lock = std::scoped_lock{state.mutex};
        state.armed = false;
        state.released = true;
    }
    state.changed.notify_all();
}

auto PasswordHashPause::wait_until_hashing(std::chrono::milliseconds timeout) const -> bool
{
    auto& state = pause_state();
    auto lock = std::unique_lock{state.mutex};
    return state.changed.wait_for(lock, timeout, [&state] {
        return state.hashing;
    });
}

void PasswordHashPause::release() const
{
    auto& state = pause_state();
    {
        auto const lock = std::scoped_lock{state.mutex};
        state.released = true;
    }
    state.changed.notify_all();
}

namespace detail
{

    void pause_password_hash_if_armed()
    {
        auto& state = pause_state();
        auto lock = std::unique_lock{state.mutex};
        if (!state.armed || state.hashing)
        {
            return;
        }
        state.hashing = true;
        state.changed.notify_all();
        state.changed.wait(lock, [&state] {
            return state.released;
        });
    }

} // namespace detail

} // namespace merovingian::tests
