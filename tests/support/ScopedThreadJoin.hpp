// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <thread>

namespace merovingian::tests::tls_mock
{

// Joins a mock-server thread on scope exit. A failing REQUIRE unwinds the
// enclosing scope, and destroying a still-joinable std::thread calls
// std::terminate — so an assertion failure would abort the whole test binary
// instead of reporting. Every mock server here has a bounded accept timeout, so
// the join always completes. Joining twice is safe: the explicit join() in the
// happy path leaves the thread non-joinable.
class ScopedThreadJoin final
{
public:
    explicit ScopedThreadJoin(std::thread& thread) noexcept
        : thread_{thread}
    {
    }

    ~ScopedThreadJoin()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    ScopedThreadJoin(ScopedThreadJoin const&) = delete;
    auto operator=(ScopedThreadJoin const&) -> ScopedThreadJoin& = delete;
    ScopedThreadJoin(ScopedThreadJoin&&) = delete;
    auto operator=(ScopedThreadJoin&&) -> ScopedThreadJoin& = delete;

private:
    std::thread& thread_;
};

} // namespace merovingian::tests::tls_mock
