// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/portable_semaphore.hpp"

#include <algorithm>
#include <cstddef>
#include <future>
#include <utility>
#include <vector>

namespace merovingian::core
{

// Runs task(i) for every i in [0, count), each on its own std::async thread,
// with at most `parallelism` running at once (a parallelism of 0 counts as 1).
// Returns only once every task has finished.
//
// A task's slot is held by a SemaphorePermit that the task moves onto its own
// stack, so the slot comes back when the task returns or throws, and also if
// std::async fails to launch it. Releasing by hand at the end of the task body
// leaks the slot on a throw, and after `parallelism` throws the next acquire
// waits forever.
//
// If any task throws, the exception of the lowest-indexed one is rethrown, but
// only after every task has been joined, so nothing still running can touch
// state the caller is unwinding.
template <typename Task>
auto run_bounded_parallel(std::size_t const count, std::size_t const parallelism, Task const& task) -> void
{
    auto semaphore = PortableSemaphore{std::max(std::size_t{1U}, parallelism)};
    // Declared after the semaphore so it is destroyed first: a std::async
    // future's destructor joins its task, which still holds a permit.
    auto tasks = std::vector<std::future<void>>{};
    tasks.reserve(count);
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        semaphore.acquire();
        auto permit = SemaphorePermit{semaphore};
        tasks.push_back(std::async(std::launch::async, [&task, index, permit = std::move(permit)]() mutable {
            // Moved off the future's stored callable, which can outlive the
            // task, so the slot is returned the moment the task ends.
            auto const held = std::move(permit);
            task(index);
        }));
    }
    for (auto& running : tasks)
    {
        running.wait();
    }
    for (auto& finished : tasks)
    {
        finished.get();
    }
}

} // namespace merovingian::core
