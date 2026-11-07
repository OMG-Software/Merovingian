// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>

namespace merovingian::homeserver
{

// A stop request a background job polls between units of work, in place of
// std::stop_token: the libc++ of FreeBSD and OpenBSD provides neither
// std::stop_token nor std::jthread (ADR-0167). Once requested, a stop stays
// requested. Safe to read and request from any thread.
class StopFlag final
{
public:
    [[nodiscard]] auto stop_requested() const noexcept -> bool
    {
        return requested_.load(std::memory_order_acquire);
    }

    auto request_stop() noexcept -> void
    {
        requested_.store(true, std::memory_order_release);
    }

private:
    std::atomic<bool> requested_{false};
};

} // namespace merovingian::homeserver
