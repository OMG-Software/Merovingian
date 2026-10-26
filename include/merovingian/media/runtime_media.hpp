// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/media/security.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

struct RuntimeMediaConfig final
{
    std::uint64_t max_upload_bytes{0U};
    // Repository capacity limits (0.12.5 audit, finding 19; 0.12.12 audit,
    // finding MED-6). The in-memory media index had no cap on total records,
    // total bytes, or per-user usage, so upload spam or a large remote-media
    // cache grew it until the process was OOM-killed. An upload that would
    // cross any of these is refused with 507 rather than evicting: media is
    // addressable content a client already holds an mxc:// URI for, so silently
    // dropping the oldest blob would turn a capacity problem into broken links.
    //
    // Parsed from the media config keys of the same name. The configuration
    // defaults are non-zero; an explicit empty config value still maps to 0,
    // preserving the pre-0.12.5 unbounded behaviour for operators who opt out.
    std::uint64_t max_records{0U};
    std::uint64_t max_total_bytes{0U};
    std::uint64_t max_bytes_per_user{0U};
    std::vector<std::string> allowed_mime_types{"image/png", "image/jpeg", "image/gif", "text/plain",
                                                "application/pdf"};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    // Acceptance disposition for authenticated local uploads. Defaults to
    // allow_after_scan, matching the only behaviour that existed before this
    // policy was introduced.
    MediaAcceptancePolicy local_upload_policy{MediaAcceptancePolicy::allow_after_scan};
    // Acceptance disposition for bytes fetched from a federated origin server.
    // Defaults to quarantine: unlike a local upload, remote media has no
    // accountable local identity behind it and no real scanner verdict is
    // ever produced for it today, so every fetch is held for admin review
    // until an operator explicitly opts into a looser policy.
    MediaAcceptancePolicy remote_fetch_media_policy{MediaAcceptancePolicy::quarantine};
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
    // Remote media cache (0.12.12 audit, finding OUT-4). Fetched remote media is
    // keyed by (origin_server, media_id) so repeated requests within the TTL serve
    // the already-stored local record instead of re-fetching and re-storing.
    // The cache is bounded by max_entries with LRU eviction when it is full.
    std::uint64_t remote_media_cache_max_entries{50000U};
    std::uint32_t remote_media_cache_ttl_seconds{86400U};
    // ADR-0120: the remote cache's own byte budget; 0 means no limit.
    std::uint64_t remote_media_cache_max_bytes{0U};
    // Absolute path to the out-of-process thumbnail worker. Empty disables
    // resampling (the original media bytes are served instead). Defaults to the
    // build-time install location; see make_runtime_media_config.
    std::string thumbnail_worker_path{};
    // Pre-opened file descriptor for the thumbnail worker binary. Set to a valid
    // fd before entering FreeBSD Capsicum capability mode so the child process can
    // exec the worker with fexecve(3) rather than execv(3). -1 means unused.
    int thumbnail_worker_fd{-1};
    std::uint32_t thumbnail_timeout_seconds{10U};
    // MED-4, ADR-0152: the thumbnail cache's byte budget (0 disables it) and the
    // per-requester cap on concurrent decodes.
    std::uint64_t thumbnail_cache_max_bytes{64U * 1024U * 1024U};
    std::uint32_t thumbnail_max_concurrent_per_user{2U};
    // ADR-0212: asynchronous uploads (POST /_matrix/media/v1/create). How long
    // a reserved media ID lives unused, how many live reservations one user
    // and the whole server may hold, and the longest a download of a reserved
    // ID waits for its content.
    std::uint64_t pending_upload_ttl_ms{86400000U};
    std::uint32_t max_pending_uploads_per_user{10U};
    std::uint64_t max_pending_uploads{10000U};
    std::uint32_t pending_upload_max_wait_ms{20000U};
    // ADR-0213: URL previews (GET /_matrix/client/v1/media/preview_url). Off
    // unless the operator enables them.
    bool url_preview_enabled{false};
    std::uint64_t url_preview_max_page_bytes{1024U * 1024U};
    std::uint64_t url_preview_max_image_bytes{5U * 1024U * 1024U};
    std::uint32_t url_preview_timeout_seconds{10U};
    std::uint32_t url_preview_max_redirects{3U};
    std::uint32_t url_preview_cache_ttl_seconds{3600U};
    std::uint32_t url_preview_cache_max_entries{1000U};
    // security.federation.allow_private_ip_ranges (ADR-0230): remote media is
    // fetched from a federation peer, so the same networks are reachable.
    // URL preview does not use this.
    std::vector<std::string> allowed_private_fetch_ranges{};
};

[[nodiscard]] auto make_runtime_media_config(config::Config const& config) -> RuntimeMediaConfig;
[[nodiscard]] auto media_summary(RuntimeMediaConfig const& config) -> std::string;

} // namespace merovingian::media
