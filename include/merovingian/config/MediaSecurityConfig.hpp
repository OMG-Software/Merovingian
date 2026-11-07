// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::config
{

struct MediaSecurityConfig final
{
    std::string max_upload_size{"50MiB"};
    // Repository capacity limits (0.12.5 audit, finding 19; 0.12.12 audit,
    // finding MED-6). The in-memory media index was unbounded, so upload spam
    // or a large remote-media cache could exhaust memory. An upload that would
    // cross any of these is refused with 507 M_LIMIT_EXCEEDED rather than
    // evicting an older blob: clients hold mxc:// URIs for what is already
    // stored, and eviction would break them. Empty explicitly means no limit;
    // the defaults below are non-zero so an unconfigured server is bounded.
    // Media bytes live in the database (ADR-0119), so these bound storage; the
    // defaults suit a community server (ADR-0113). max_size_per_user must stay
    // at or above max_upload_size, or one legitimate upload is refused. These
    // apply to local media only: cached remote media has its own budget below
    // (ADR-0120). Each record's metadata is still held in memory, so
    // max_records also bounds memory (roughly 300-500 bytes per record).
    std::string max_total_size{"250GiB"};
    std::string max_size_per_user{"10GiB"};
    std::uint64_t max_records{1000000U};
    // F-46, ADR-0340: one user's share of max_records, so a single account
    // cannot fill the server-wide cap and refuse every other user. Counts live
    // local records, deduplicated or not. 0 means no per-user limit.
    std::uint64_t max_records_per_user{20000U};
    std::vector<std::string> allowed_mime_types{};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    // Acceptance disposition for authenticated local uploads. One of "allow",
    // "allow-after-scan", "quarantine", "deny". Validated by validate_config()
    // via is_valid_media_acceptance_policy(); parsed into
    // media::MediaAcceptancePolicy by media::make_runtime_media_config().
    std::string local_upload_policy{"allow-after-scan"};
    // Acceptance disposition for bytes fetched from a federated origin
    // server. Defaults to "quarantine" rather than mirroring
    // local_upload_policy's default: remote media has no accountable local
    // uploader and, unlike a local upload, is never covered by a real scanner
    // verdict today, so it is held for admin review unless an operator opts
    // into a looser policy.
    std::string remote_fetch_media_policy{"quarantine"};
    bool block_private_ip_fetches{true};
    std::string remote_fetch_timeout{"30s"};
    bool remote_fetch_enabled{false};
    bool decode_in_sandbox{true};
    // OUT-4: remote media cache settings. The cache is keyed by (origin_server,
    // media_id) and holds the local media_id that was assigned when the remote
    // bytes were first admitted. TTL is in seconds; max_entries caps in-memory
    // mappings. A max_entries of 0 disables caching.
    std::uint32_t remote_media_cache_ttl_seconds{86400U};
    std::uint64_t remote_media_cache_max_entries{50000U};
    // ADR-0120: bytes of cached remote media. The least recently used remote
    // files are deleted to stay within it, so remote caching never takes
    // capacity from local uploads. Empty means no limit.
    std::string remote_media_cache_max_size{"25GiB"};
    // MED-4, ADR-0152: bytes of generated thumbnails kept in memory (least
    // recently used first out; empty or 0 disables the cache), and how many
    // thumbnail decodes one requester may run at once.
    std::string thumbnail_cache_size{"64MiB"};
    std::uint32_t thumbnail_max_concurrent_per_user{2U};
    // ADR-0212: asynchronous uploads (POST /_matrix/media/v1/create, PUT
    // /_matrix/media/v3/upload/{serverName}/{mediaId}). The spec recommends a
    // 24 hour unused-ID lifetime. A user past max_pending_uploads_per_user, or
    // the server past max_pending_uploads, gets 429 M_LIMIT_EXCEEDED. A
    // download of a reserved ID waits at most pending_upload_max_wait_ms (and
    // never longer than the request's timeout_ms) for the content.
    std::uint32_t pending_upload_ttl_seconds{86400U};
    std::uint32_t max_pending_uploads_per_user{10U};
    std::uint64_t max_pending_uploads{10000U};
    std::uint32_t pending_upload_max_wait_ms{20000U};
    // ADR-0213: URL previews (GET /_matrix/client/v1/media/preview_url). The
    // server fetches a URL a client names, so it is off by default. Fetches are
    // SSRF-gated on every redirect hop and capped in bytes, time and hops;
    // results are cached in memory.
    bool url_preview_enabled{false};
    std::string url_preview_max_page_size{"1MiB"};
    std::string url_preview_max_image_size{"5MiB"};
    std::uint32_t url_preview_timeout_seconds{10U};
    std::uint32_t url_preview_max_redirects{3U};
    std::uint32_t url_preview_cache_ttl_seconds{3600U};
    std::uint32_t url_preview_cache_max_entries{1000U};
};

} // namespace merovingian::config
