// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

struct RuntimeMediaConfig final
{
    std::uint64_t max_upload_bytes{0U};
    std::vector<std::string> allowed_mime_types{"image/png", "image/jpeg", "image/gif", "text/plain",
                                                "application/pdf"};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    bool private_address_fetches_blocked{true};
    std::uint32_t remote_fetch_timeout_seconds{0U};
    bool remote_fetch_enabled{false};
    bool decode_in_sandbox{true};
    std::uint64_t max_decode_input_bytes{0U};
    std::uint64_t max_decode_output_bytes{0U};
    std::uint64_t max_decode_pixels{4096000U};
    std::uint64_t max_animation_frames{1U};
    std::uint64_t max_decompression_ratio{64U};
    bool thumbnailing_enabled{true};
    // Absolute path to the out-of-process thumbnail worker. Empty disables
    // resampling (the original media bytes are served instead). Defaults to the
    // build-time install location; see make_runtime_media_config.
    std::string thumbnail_worker_path{};
    // Pre-opened file descriptor for the thumbnail worker binary. Set to a valid
    // fd before entering FreeBSD Capsicum capability mode so the child process can
    // exec the worker with fexecve(3) rather than execv(3). -1 means unused.
    int thumbnail_worker_fd{-1};
    std::uint32_t thumbnail_timeout_seconds{10U};
};

[[nodiscard]] auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig;
[[nodiscard]] auto media_summary(RuntimeMediaConfig const& config) -> std::string;

} // namespace merovingian::media
