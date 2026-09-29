// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <filesystem>
#include <system_error>

namespace merovingian::tests
{

// Number of tasks (threads) currently in this process, read from
// /proc/self/task. Returns 0 where /proc is unavailable (non-Linux), so callers
// that compare two counts must not treat 0 as "no threads".
[[nodiscard]] inline auto count_process_tasks() -> std::size_t
{
    auto count = std::size_t{0U};
    auto ec = std::error_code{};
    for (auto it = std::filesystem::directory_iterator{"/proc/self/task", ec};
         !ec && it != std::filesystem::directory_iterator{}; it.increment(ec))
    {
        ++count;
    }
    return count;
}

} // namespace merovingian::tests
