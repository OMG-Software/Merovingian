// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/runtime_media.hpp"

#include <string>
#include <vector>

// Build-time default install path of the sandboxed thumbnail worker. Mirrors the
// MEROVINGIAN_SYSCONFDIR convention; defined by the media library's cpp_args.
#ifndef MEROVINGIAN_THUMBNAIL_WORKER_PATH
#define MEROVINGIAN_THUMBNAIL_WORKER_PATH ""
#endif

namespace merovingian::media
{
namespace
{

    [[nodiscard]] auto default_allowed_mime_types() -> std::vector<std::string>
    {
        // application/octet-stream is intentionally included so encrypted-room
        // attachments (which clients upload as opaque ciphertext) are not
        // quarantined by default. The server cannot sniff the underlying format
        // without decrypting the attachment.
        return {"image/png", "image/jpeg", "image/gif", "text/plain", "application/pdf", "application/octet-stream"};
    }

} // namespace

auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig
{
    auto const upload_limit = config::parse_size_limit(config.security().media.max_upload_size);
    // Empty (the default) parses as invalid, which maps to 0 — no limit.
    auto const total_limit = config::parse_size_limit(config.security().media.max_total_size);
    auto const per_user_limit = config::parse_size_limit(config.security().media.max_size_per_user);
    auto const remote_cache_limit = config::parse_size_limit(config.security().media.remote_media_cache_max_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().media.remote_fetch_timeout);
    auto const& configured_types = config.security().media.allowed_mime_types;
    auto allowed_types =
        configured_types.empty() ? default_allowed_mime_types() : std::vector<std::string>{configured_types};

    return {
        upload_limit.valid ? upload_limit.bytes : 0U,
        config.security().media.max_records,
        total_limit.valid ? total_limit.bytes : 0U,
        per_user_limit.valid ? per_user_limit.bytes : 0U,
        std::move(allowed_types),
        config.security().media.quarantine_unknown_mime,
        config.security().media.enable_av_scanner,
        parse_media_acceptance_policy(config.security().media.local_upload_policy),
        parse_media_acceptance_policy(config.security().media.remote_fetch_media_policy),
        config.security().media.block_private_ip_fetches,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
        config.security().media.remote_fetch_enabled,
        config.security().media.decode_in_sandbox,
        upload_limit.valid ? upload_limit.bytes : 0U,
        upload_limit.valid ? upload_limit.bytes * 64U : 0U,
        4096000U,
        1U,
        64U,
        true,
        config.security().media.remote_media_cache_max_entries,
        config.security().media.remote_media_cache_ttl_seconds,
        remote_cache_limit.valid ? remote_cache_limit.bytes : 0U,
        std::string{MEROVINGIAN_THUMBNAIL_WORKER_PATH},
        10U,
    };
}

auto media_summary(RuntimeMediaConfig const& config) -> std::string
{
    // OPS-3: the effective quotas, so an operator can see what a size limit
    // was read as; 0 means no limit.
    return "Media runtime config: max_upload_bytes=" + std::to_string(config.max_upload_bytes) +
           " max_total_bytes=" + std::to_string(config.max_total_bytes) +
           " max_bytes_per_user=" + std::to_string(config.max_bytes_per_user) +
           " max_records=" + std::to_string(config.max_records) +
           " remote_media_cache_max_bytes=" + std::to_string(config.remote_media_cache_max_bytes) +
           " remote_media_cache_max_entries=" + std::to_string(config.remote_media_cache_max_entries) +
           " allowed_mime_types=" + std::to_string(config.allowed_mime_types.size()) +
           " remote_fetch_timeout_seconds=" + std::to_string(config.remote_fetch_timeout_seconds) +
           " remote_fetch_enabled=" + std::string{config.remote_fetch_enabled ? "true" : "false"} +
           " private_address_fetches_blocked=" +
           std::string{config.private_address_fetches_blocked ? "true" : "false"} +
           " decode_in_sandbox=" + std::string{config.decode_in_sandbox ? "true" : "false"} +
           " thumbnailing_enabled=" + std::string{config.thumbnailing_enabled ? "true" : "false"};
}

} // namespace merovingian::media
