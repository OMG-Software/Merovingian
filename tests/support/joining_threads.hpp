// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <thread>
#include <utility>
#include <vector>

namespace merovingian::tests
{

// Threads that are all joined when this goes out of scope: the part of
// std::jthread the concurrency scenarios rely on, without std::jthread, which
// the libc++ shipped on FreeBSD and OpenBSD does not provide. Joining in the
// destructor also means a REQUIRE that throws mid-scenario unwinds cleanly
// instead of destroying a joinable std::thread (std::terminate).
class JoiningThreads final
{
public:
    JoiningThreads() = default;

    ~JoiningThreads()
    {
        for (auto& thread : threads_)
        {
            if (thread.joinable())
            {
                thread.join();
            }
        }
    }

    JoiningThreads(JoiningThreads const&) = delete;
    auto operator=(JoiningThreads const&) -> JoiningThreads& = delete;
    JoiningThreads(JoiningThreads&&) = delete;
    auto operator=(JoiningThreads&&) -> JoiningThreads& = delete;

    template <typename Function>
    auto emplace_back(Function&& function) -> void
    {
        threads_.emplace_back(std::forward<Function>(function));
    }

private:
    std::vector<std::thread> threads_{};
};

} // namespace merovingian::tests
