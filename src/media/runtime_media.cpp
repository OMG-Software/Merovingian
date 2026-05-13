// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/runtime_media.hpp"

#include <string>
#include <vector>

namespace merovingian::media
{
namespace
{

[[nodiscard]] auto default_allowed_mime_types() -> std::vector<std::string>
{
    return {"image/png", "image/jpeg", "image/gif", "text/plain", "application/pdf"};
}

} // namespace

auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig
{
    auto const upload_limit = config::parse_size_limit(config.security().media.max_upload_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().media.remote_fetch_timeout);

    return {
        upload_limit.valid ? upload_limit.bytes : 0U,
        default_allowed_mime_types(),
        config.security().media.quarantine_unknown_mime,
        config.security().media.enable_av_scanner,
        config.security().media.block_private_ip_fetches,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
        false,
        config.security().media.decode_in_sandbox,
    };
}

auto media_summary(RuntimeMediaConfig const& config) -> std::string
{
    return "Media runtime config: max_upload_bytes=" + std::to_string(config.max_upload_bytes)
        + " allowed_mime_types=" + std::to_string(config.allowed_mime_types.size())
        + " remote_fetch_timeout_seconds=" + std::to_string(config.remote_fetch_timeout_seconds)
        + " remote_fetch_enabled=" + std::string{config.remote_fetch_enabled ? "true" : "false"}
        + " private_address_fetches_blocked=" + std::string{config.private_address_fetches_blocked ? "true" : "false"}
        + " decode_in_sandbox=" + std::string{config.decode_in_sandbox ? "true" : "false"};
}

} // namespace merovingian::media
