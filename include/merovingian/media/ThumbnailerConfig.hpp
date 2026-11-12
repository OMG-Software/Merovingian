// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// Configuration for spawning the out-of-process worker.
struct ThumbnailerConfig final
{
    std::string worker_path{};          // absolute path to the worker executable
    std::uint32_t timeout_seconds{10U}; // wall-clock cap on a single decode
    std::uint64_t max_input_bytes{0U};  // 0 = unbounded; reject larger sources
    std::uint64_t max_output_bytes{0U}; // 0 = the ceiling for the requested size; reject larger results
    std::uint32_t max_pixels{4096000U}; // decode-bomb guard handed to the worker
    std::uint32_t max_target_dimension{2048U};
    // Pre-opened fd for the worker binary (FreeBSD Capsicum only). When >= 0 the
    // child process calls fexecve(fd,...) instead of execv(path,...) so the exec
    // succeeds after cap_enter() has forbidden opening files by path. -1 disables.
    int worker_binary_fd{-1};
};

} // namespace merovingian::media
