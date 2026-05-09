// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/runtime_media.hpp>

#include <string>

namespace merovingian::media
{

auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig
{
    auto const upload_limit = config::parse_size_limit(config.security().media.max_upload_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().media.remote_fetch_timeout);

    return {
        upload_limit.valid ? upload_limit.bytes : 0U,
        config.security().media.quarantine_unknown_mime,
        config.security().media.enable_av_scanner,
        config.security().media.block_private_ip_fetches,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
        config.security().media.decode_in_sandbox,
    };
}

auto media_summary(RuntimeMediaConfig const& config) -> std::string
{
    return "Media runtime config: max_upload_bytes=" + std::to_string(config.max_upload_bytes)
        + " remote_fetch_timeout_seconds=" + std::to_string(config.remote_fetch_timeout_seconds)
        + " private_address_fetches_blocked=" + std::string{config.private_address_fetches_blocked ? "true" : "false"}
        + " decode_in_sandbox=" + std::string{config.decode_in_sandbox ? "true" : "false"};
}

} // namespace merovingian::media
