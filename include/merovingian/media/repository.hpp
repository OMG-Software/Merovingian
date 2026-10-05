// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/runtime_media.hpp"
#include "merovingian/observability/observability.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::media
{

enum class LocalMediaState
{
    available,
    quarantined,
    removed,
};

enum class LocalMediaAdminAction
{
    quarantine,
    release,
    remove,
};

struct LocalMediaBlob final
{
    std::string storage_id{};
    std::string hash_algorithm{};
    std::string digest{};
    std::uint64_t size_bytes{0U};
    std::string bytes{};
    std::uint64_t ref_count{0U};
};

struct LocalMediaThumbnail final
{
    std::string media_id{};
    std::string storage_id{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string content_type{"image/png"};
    std::uint64_t size_bytes{0U};
};

struct LocalMediaRecord final
{
    std::string media_id{};
    std::string owner_user_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    std::string storage_id{};
    LocalMediaState state{LocalMediaState::available};
    std::string quarantine_reason{};
    // True when the media was uploaded before the authenticated-media upgrade
    // and may still be served by the legacy unauthenticated v3 endpoints.
    // New uploads are minted with false, so /_matrix/media/v3/download and
    // /thumbnail fail closed to 404 while /_matrix/client/v1/media/... remains
    // available (Matrix v1.19 authenticated media, security audit M05).
    bool legacy_endpoint_visible{false};
};

struct MediaRepositoryMetrics final
{
    std::uint64_t uploads_accepted{0U};
    std::uint64_t uploads_rejected{0U};
    std::uint64_t uploads_quarantined{0U};
    std::uint64_t downloads_served{0U};
    std::uint64_t downloads_blocked{0U};
    std::uint64_t deduplicated_uploads{0U};
    std::uint64_t admin_quarantines{0U};
    std::uint64_t admin_releases{0U};
    std::uint64_t admin_removals{0U};
    std::uint64_t remote_fetch_rejections{0U};
    std::uint64_t remote_fetches_accepted{0U};
    std::uint64_t processing_rejections{0U};
    std::uint64_t thumbnails_generated{0U};
    std::uint64_t thumbnails_served{0U};
    std::uint64_t stored_blobs{0U};
    std::uint64_t stored_bytes{0U};
};

struct RemoteMediaCacheEntry final
{
    std::string origin_server{};
    std::string media_id{};
    std::string local_media_id{};
    std::uint64_t expires_at_ms{0U};
    std::uint64_t last_access_ms{0U};
};

struct LocalMediaRepository final
{
    RuntimeMediaConfig config{};
    std::vector<LocalMediaRecord> records{};
    std::vector<LocalMediaBlob> blobs{};
    std::vector<LocalMediaThumbnail> thumbnails{};
    MediaRepositoryMetrics metrics{};
    // Indices rebuilt lazily by find_local_media_record/blob. They keep
    // O(1) lookup even when the repository holds the default-capped number
    // of records (MED-6).
    std::unordered_map<std::string, std::size_t> record_index{};
    std::unordered_map<std::string, std::size_t> blob_index{};
    // Remote media cache keyed by (origin_server, media_id) with TTL/LRU
    // eviction (OUT-4).
    std::vector<RemoteMediaCacheEntry> remote_media_cache{};
};

struct LocalMediaUploadRequest final
{
    std::string owner_user_id{};
    std::string declared_mime_type{};
    std::string sniffed_mime_type{};
    std::string bytes{};
    bool scanner_clean{true};
    std::uint64_t decoded_size_bytes{0U};
    std::uint64_t pixel_count{0U};
    std::uint64_t animation_frame_count{1U};
    bool decoder_marked_safe{true};
    // True when these bytes came from fetch_remote_media() rather than a
    // client's own upload. Selects RuntimeMediaConfig::remote_fetch_media_policy
    // instead of local_upload_policy when evaluating acceptance.
    bool from_remote_fetch{false};
};

struct LocalMediaUploadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string media_id{};
    std::string content_uri{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    bool deduplicated{false};
    bool quarantined{false};
    std::string reason{};
};

struct LocalMediaDownloadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string content_type{};
    std::string bytes{};
    std::string reason{};
};

struct LocalMediaAdminResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string media_id{};
    LocalMediaState state{LocalMediaState::available};
    std::string reason{};
};

struct RemoteMediaDownloadRequest final
{
    std::string origin_server{};
    std::string media_id{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    std::string content_type{};
    std::string bytes{};
    bool scanner_clean{true};
    std::uint64_t decoded_size_bytes{0U};
    std::uint64_t pixel_count{0U};
    std::uint64_t animation_frame_count{1U};
    bool decoder_marked_safe{true};
};

struct RemoteMediaDownloadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
    std::string content_type{};
    std::string bytes{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    std::string storage_id{};
    std::string local_media_id{};
    bool quarantined{false};
};

[[nodiscard]] auto local_media_state_name(LocalMediaState state) noexcept -> char const*;
[[nodiscard]] auto make_local_media_repository(RuntimeMediaConfig config) -> LocalMediaRepository;
[[nodiscard]] auto make_local_media_storage_id(std::string_view digest, std::uint64_t size_bytes) -> std::string;
[[nodiscard]] auto calculate_media_digest(std::string_view bytes) -> std::string;
[[nodiscard]] auto media_repository_summary(LocalMediaRepository const& repository) -> std::string;
[[nodiscard]] auto media_repository_metrics(LocalMediaRepository const& repository)
    -> std::vector<observability::MetricSample>;
[[nodiscard]] auto find_local_media_record(LocalMediaRepository& repository, std::string_view media_id) noexcept
    -> LocalMediaRecord const*;
[[nodiscard]] auto find_local_media_blob(LocalMediaRepository& repository, std::string_view storage_id) noexcept
    -> LocalMediaBlob const*;
[[nodiscard]] auto find_local_media_thumbnail(LocalMediaRepository const& repository,
                                              std::string_view media_id) noexcept -> LocalMediaThumbnail const*;
auto restore_local_media_repository(LocalMediaRepository& repository, std::vector<LocalMediaRecord> records,
                                    std::vector<LocalMediaBlob> blobs) -> void;
[[nodiscard]] auto upload_local_media(LocalMediaRepository& repository, std::string_view server_name,
                                      LocalMediaUploadRequest const& request) -> LocalMediaUploadResult;
[[nodiscard]] auto download_local_media(LocalMediaRepository& repository, std::string_view server_name,
                                        std::string_view media_id, bool legacy_endpoint = false)
    -> LocalMediaDownloadResult;
// Performs the same input and current-record checks as the moderation actions
// without changing repository state, counters, or logs. Call before durable
// moderation writes so persistence failure cannot leave a partial mutation.
[[nodiscard]] auto validate_local_media_admin_action(LocalMediaRepository const& repository, std::string_view media_id,
                                                     LocalMediaAdminAction action, std::string_view reason = {})
    -> LocalMediaAdminResult;
[[nodiscard]] auto quarantine_local_media(LocalMediaRepository& repository, std::string_view media_id,
                                          std::string_view reason) -> LocalMediaAdminResult;
[[nodiscard]] auto release_local_media(LocalMediaRepository& repository, std::string_view media_id)
    -> LocalMediaAdminResult;
[[nodiscard]] auto remove_local_media(LocalMediaRepository& repository, std::string_view media_id,
                                      std::string_view reason) -> LocalMediaAdminResult;
[[nodiscard]] auto fetch_remote_media_disabled(LocalMediaRepository& repository,
                                               RemoteMediaDownloadRequest const& request) -> RemoteMediaDownloadResult;
[[nodiscard]] auto fetch_remote_media(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request)
    -> RemoteMediaDownloadResult;

// Body and outer Content-Type for a v1.19 federation media download response.
// The body is a multipart/mixed envelope with an empty JSON metadata part and
// a second part carrying the media bytes.
struct FederationMediaDownloadBody final
{
    std::string body{};
    std::string content_type{};
};

// Builds a Matrix v1.19 federation media download response body. Returns an
// empty result if the multipart envelope could not be assembled.
[[nodiscard]] auto build_federation_media_download_body(std::string_view media_content_type, std::string_view bytes)
    -> FederationMediaDownloadBody;

} // namespace merovingian::media
