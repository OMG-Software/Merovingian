// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/FederationMediaDownloadBody.hpp"
#include "merovingian/media/LocalMediaAdminAction.hpp"
#include "merovingian/media/LocalMediaAdminResult.hpp"
#include "merovingian/media/LocalMediaBlob.hpp"
#include "merovingian/media/LocalMediaDownloadTarget.hpp"
#include "merovingian/media/LocalMediaRecord.hpp"
#include "merovingian/media/LocalMediaState.hpp"
#include "merovingian/media/LocalMediaThumbnail.hpp"
#include "merovingian/media/LocalMediaUploadRequest.hpp"
#include "merovingian/media/LocalMediaUploadResult.hpp"
#include "merovingian/media/MediaRepositoryMetrics.hpp"
#include "merovingian/media/PendingMediaUpload.hpp"
#include "merovingian/media/PendingMediaUploadPlan.hpp"
#include "merovingian/media/PendingUploadAdmission.hpp"
#include "merovingian/media/RemoteMediaCacheEntry.hpp"
#include "merovingian/media/RemoteMediaDownloadRequest.hpp"
#include "merovingian/media/RemoteMediaDownloadResult.hpp"
#include "merovingian/media/RuntimeMediaConfig.hpp"
#include "merovingian/media/ThumbnailCache.hpp"
#include "merovingian/observability/MetricSample.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::media
{

// Whether a persisted owner string names the remote media cache (ADR-0120): the
// "@remote-media:<origin>" owner of a server other than `local_server_name`. A local account's
// user ID always carries the local server name, and this server never caches media it fetched
// from itself, so a local account named "remote-media" never matches. Used to rebuild
// LocalMediaRecord::from_remote_fetch when records are hydrated.
[[nodiscard]] auto is_remote_cache_owner(std::string_view owner_user_id, std::string_view local_server_name) noexcept
    -> bool;

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
    // MED-4, ADR-0152: generated thumbnails, and thumbnail decodes in flight per
    // requester. Both guarded by runtime.mutex like the rest of the repository.
    ThumbnailCache thumbnail_cache{};
    std::unordered_map<std::string, std::uint32_t> thumbnail_decodes_in_flight{};
    // ADR-0212: reservations made by POST /_matrix/media/v1/create, keyed by
    // media ID. Bounded by RuntimeMediaConfig::max_pending_uploads.
    std::unordered_map<std::string, PendingMediaUpload> pending_uploads{};
    // F-46, ADR-0340: how many live (not removed) local records each owner
    // holds, so the per-user record share is checked in O(1) under
    // runtime.mutex. Cached remote media is never counted. Kept in step on
    // insert, erase, removal and hydration; `owner_record_counts_basis` is
    // records.size() when the map was last known to match, and a mismatch
    // (records changed behind the repository's back) rebuilds it.
    std::unordered_map<std::string, std::uint64_t> owner_record_counts{};
    std::size_t owner_record_counts_basis{0U};
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
// DB-5: undoes the upload that created `media_id` when it could not be made
// durable, so memory matches the database again: the record and its thumbnail
// entry are removed and the blob reference it took is released. Returns false
// when no record has that ID.
[[nodiscard]] auto rollback_local_media_upload(LocalMediaRepository& repository, std::string_view media_id) -> bool;

// Plans a reservation for `owner_user_id` at `now_ms`: 429 when the user
// already holds max_pending_uploads_per_user live reservations or the server
// max_pending_uploads. Changes nothing; see apply_pending_media_upload.
[[nodiscard]] auto plan_pending_media_upload(LocalMediaRepository& repository, std::string_view owner_user_id,
                                             std::uint64_t now_ms) -> PendingMediaUploadPlan;
// Applies a plan the database has committed.
auto apply_pending_media_upload(LocalMediaRepository& repository, PendingMediaUploadPlan const& plan) -> void;
// Hydration: replaces the reservations with `reservations`.
auto restore_pending_media_uploads(LocalMediaRepository& repository, std::vector<PendingMediaUpload> reservations)
    -> void;
// The live (unexpired) reservation for `media_id`, or nullptr.
[[nodiscard]] auto find_pending_media_upload(LocalMediaRepository const& repository, std::string_view media_id,
                                             std::uint64_t now_ms) noexcept -> PendingMediaUpload const*;
[[nodiscard]] auto admit_pending_media_upload(LocalMediaRepository& repository, std::string_view media_id,
                                              std::string_view user_id, std::uint64_t now_ms) -> PendingUploadAdmission;
// Forgets the reservation for `media_id` once its content is durable.
auto complete_pending_media_upload(LocalMediaRepository& repository, std::string_view media_id) -> void;

// Resolves a local media download to the blob that holds its bytes, applying
// the record checks (state, legacy visibility). Reads no bytes.
[[nodiscard]] auto resolve_local_media_download(LocalMediaRepository& repository, std::string_view media_id,
                                                bool legacy_endpoint = false) -> LocalMediaDownloadTarget;
// True while `media_id` may still be served from `storage_id`: available, not
// moved to another blob, the blob still referenced, and visible to the legacy
// endpoints when `legacy_endpoint`. Checked again after bytes are read without
// the runtime mutex, so media removed or quarantined meanwhile is not served.
[[nodiscard]] auto local_media_still_servable(LocalMediaRepository& repository, std::string_view media_id,
                                              std::string_view storage_id, bool legacy_endpoint = false) -> bool;
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
// OUT-4 / ADR-0119: the stored local record for remote media (origin_server,
// media_id) whose cache entry has not expired, in whatever state moderation
// has left it, or nullptr. Callers consult this before discovery and the
// network: an available record is served, a quarantined or removed one is
// refused, and neither costs an outbound request. A hit becomes the most
// recently used entry. An expired entry is kept, so the admission that
// replaces it can release its stored copy.
[[nodiscard]] auto find_cached_remote_media(LocalMediaRepository& repository, std::string_view origin_server,
                                            std::string_view media_id, std::uint64_t now_ms) -> LocalMediaRecord const*;
// Wall-clock milliseconds since the Unix epoch: cache entries are persisted, so
// their times must mean the same thing after a restart.
[[nodiscard]] auto remote_media_cache_now_ms() noexcept -> std::uint64_t;
// ADR-0119: the cache entries admitting new media for (origin_server,
// media_id) displaces: any entry for the same key, and the least recently used
// entries beyond remote_media_cache_max_entries. A cap of 0 disables caching:
// every other entry is displaced and the new one is stored already expired, so
// at most one remote copy is kept. Changes nothing; see
// apply_remote_media_admission.
// `incoming_size_bytes` is the new file's size: least recently used entries are
// also displaced until it fits remote_media_cache_max_bytes (ADR-0120).
// Entries whose lifetime ended by `now_ms` are displaced too, so they do not
// hold the caps (F-47, ADR-0341). The cost is one pass over the cache.
[[nodiscard]] auto plan_remote_media_admission(LocalMediaRepository const& repository, std::string_view origin_server,
                                               std::string_view media_id, std::uint64_t incoming_size_bytes,
                                               std::uint64_t now_ms) -> std::vector<RemoteMediaCacheEntry>;
// Applies an admission the database has committed: forgets the displaced
// entries' records and blob references, and records the new entry.
auto apply_remote_media_admission(LocalMediaRepository& repository, std::string_view origin_server,
                                  std::string_view media_id, std::string_view local_media_id, std::uint64_t now_ms,
                                  std::vector<RemoteMediaCacheEntry> const& displaced) -> void;
// Hydration: replaces the cache with `entries` whose records exist, ordered
// from least to most recently used.
auto restore_remote_media_cache(LocalMediaRepository& repository, std::vector<RemoteMediaCacheEntry> entries) -> void;
[[nodiscard]] auto fetch_remote_media_disabled(LocalMediaRepository& repository,
                                               RemoteMediaDownloadRequest const& request) -> RemoteMediaDownloadResult;
// `now_ms` is the remote media cache's clock (remote_media_cache_now_ms); the
// caller passes it so one admission uses one timestamp throughout.
[[nodiscard]] auto fetch_remote_media(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request,
                                      std::uint64_t now_ms) -> RemoteMediaDownloadResult;

// Builds a Matrix v1.19 federation media download response body. Returns an
// empty result if the multipart envelope could not be assembled. `upload_name` is the
// filename the upload was made with: when it is valid it goes into the media part's
// Content-Disposition (encoded per RFC 6266 by media_content_disposition), otherwise
// the header carries none.
[[nodiscard]] auto build_federation_media_download_body(std::string_view media_content_type, std::string_view bytes,
                                                        std::string_view upload_name = {})
    -> FederationMediaDownloadBody;

} // namespace merovingian::media
