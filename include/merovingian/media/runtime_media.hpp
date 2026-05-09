// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/config/config.hpp>

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct RuntimeMediaConfig final
{
    std::uint64_t max_upload_bytes{0U};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    bool private_address_fetches_blocked{true};
    std::uint32_t remote_fetch_timeout_seconds{0U};
    bool decode_in_sandbox{true};
};

[[nodiscard]] auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig;
[[nodiscard]] auto media_summary(RuntimeMediaConfig const& config) -> std::string;

} // namespace merovingian::media
