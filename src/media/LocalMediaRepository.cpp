// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/LocalMediaRepository.hpp"

#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/GenericHash.hpp"
#include "merovingian/crypto/Random.hpp"
#include "merovingian/media/DecoderSafetyPolicy.hpp"
#include "merovingian/media/DecoderSafetyRequest.hpp"
#include "merovingian/media/FederationMediaDownloadBody.hpp"
#include "merovingian/media/LocalMediaAdminResult.hpp"
#include "merovingian/media/LocalMediaBlob.hpp"
#include "merovingian/media/LocalMediaDownloadTarget.hpp"
#include "merovingian/media/LocalMediaRecord.hpp"
#include "merovingian/media/LocalMediaState.hpp"
#include "merovingian/media/LocalMediaThumbnail.hpp"
#include "merovingian/media/LocalMediaUploadRequest.hpp"
#include "merovingian/media/LocalMediaUploadResult.hpp"
#include "merovingian/media/MediaDisposition.hpp"
#include "merovingian/media/MediaUploadPolicy.hpp"
#include "merovingian/media/PendingMediaUpload.hpp"
#include "merovingian/media/PendingMediaUploadPlan.hpp"
#include "merovingian/media/RemoteMediaCacheEntry.hpp"
#include "merovingian/media/RemoteMediaDownloadRequest.hpp"
#include "merovingian/media/RemoteMediaDownloadResult.hpp"
#include "merovingian/media/SandboxedMediaWorkerPlan.hpp"
#include "merovingian/media/Security.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/MetricSample.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::media
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("media_repository", event, fields, severity);
    }

    [[nodiscard]] auto media_id_is_safe(std::string_view media_id) noexcept -> bool
    {
        return !media_id.empty() && media_id.find('/') == std::string_view::npos &&
               media_id.find("..") == std::string_view::npos && media_id.find(' ') == std::string_view::npos;
    }

    [[nodiscard]] auto upload_policy(RuntimeMediaConfig const& config, bool from_remote_fetch) -> MediaUploadPolicy
    {
        return {config.max_upload_bytes,
                config.allowed_mime_types,
                true,
                config.quarantine_unknown_mime,
                true,
                from_remote_fetch ? config.remote_fetch_media_policy : config.local_upload_policy};
    }

    [[nodiscard]] auto canonical_content_type(LocalMediaUploadRequest const& request) -> std::string
    {
        if (request.sniffed_mime_type.empty())
        {
            return request.declared_mime_type;
        }
        // Owner decision 2026-10-29: a declared type that only spells the sniffed one differently
        // ("img/png" for image/png) is what the uploader asked to get back. Only such a type is ever
        // kept; any other declaration is replaced by the sniffed type, which the policy judged.
        if (request.declared_mime_type != request.sniffed_mime_type &&
            media_types_are_equivalent(request.declared_mime_type, request.sniffed_mime_type))
        {
            return request.declared_mime_type;
        }
        return request.sniffed_mime_type;
    }

    auto ensure_blob_index(LocalMediaRepository& repository) -> void;
    auto ensure_record_index(LocalMediaRepository& repository) -> void;
    [[nodiscard]] auto make_storage_id(std::string_view digest, std::uint64_t size_bytes) -> std::string;

    [[nodiscard]] auto find_blob(LocalMediaRepository& repository, std::string_view storage_id) noexcept
        -> LocalMediaBlob*
    {
        ensure_blob_index(repository);
        auto const iterator = repository.blob_index.find(std::string{storage_id});
        if (iterator == repository.blob_index.end())
        {
            return nullptr;
        }
        if (iterator->second >= repository.blobs.size() || repository.blobs[iterator->second].ref_count == 0U)
        {
            return nullptr;
        }
        return &repository.blobs[iterator->second];
    }

    [[nodiscard]] auto find_record(LocalMediaRepository& repository, std::string_view media_id) noexcept
        -> LocalMediaRecord*
    {
        ensure_record_index(repository);
        auto const iterator = repository.record_index.find(std::string{media_id});
        if (iterator == repository.record_index.end())
        {
            return nullptr;
        }
        if (iterator->second >= repository.records.size())
        {
            return nullptr;
        }
        return &repository.records[iterator->second];
    }

    // The blob with the content `digest` and `size_bytes`, or nullptr. A storage ID is derived from the two, so this
    // is one index lookup (ADR-0633).
    [[nodiscard]] auto find_live_blob(LocalMediaRepository& repository, std::string_view hash_algorithm,
                                      std::string_view digest, std::uint64_t size_bytes) noexcept -> LocalMediaBlob*
    {
        auto* const blob = find_blob(repository, make_storage_id(digest, size_bytes));
        if (blob == nullptr || blob->hash_algorithm != hash_algorithm || blob->digest != digest ||
            blob->size_bytes != size_bytes)
        {
            return nullptr;
        }
        return blob;
    }

    auto refresh_storage_metrics(LocalMediaRepository& repository) -> void
    {
        ensure_blob_index(repository);
        repository.metrics.stored_blobs = repository.live_blob_total;
        repository.metrics.stored_bytes = repository.live_blob_bytes;
    }

    auto clear_repository_indices(LocalMediaRepository& repository) -> void
    {
        repository.record_index.clear();
        repository.blob_index.clear();
        repository.thumbnail_index.clear();
    }

    auto rebuild_record_index(LocalMediaRepository& repository) -> void
    {
        repository.media_rows_examined.add(repository.records.size());
        repository.record_index.clear();
        repository.record_index.reserve(repository.records.size());
        for (std::size_t i = 0U; i < repository.records.size(); ++i)
        {
            repository.record_index.emplace(repository.records[i].media_id, i);
        }
    }

    // Indexes the blobs that hold a reference and counts them and their bytes. Costs the blobs once.
    auto rebuild_blob_index(LocalMediaRepository& repository) -> void
    {
        repository.media_rows_examined.add(repository.blobs.size());
        repository.blob_index.clear();
        repository.blob_index.reserve(repository.blobs.size());
        repository.live_blob_total = 0U;
        repository.live_blob_bytes = 0U;
        for (std::size_t i = 0U; i < repository.blobs.size(); ++i)
        {
            if (repository.blobs[i].ref_count > 0U)
            {
                repository.blob_index.emplace(repository.blobs[i].storage_id, i);
                ++repository.live_blob_total;
                repository.live_blob_bytes += repository.blobs[i].size_bytes;
            }
        }
        repository.blob_counts_basis = repository.blobs.size();
    }

    auto rebuild_thumbnail_index(LocalMediaRepository& repository) -> void
    {
        repository.media_rows_examined.add(repository.thumbnails.size());
        repository.thumbnail_index.clear();
        repository.thumbnail_index.reserve(repository.thumbnails.size());
        for (std::size_t i = 0U; i < repository.thumbnails.size(); ++i)
        {
            repository.thumbnail_index.emplace(repository.thumbnails[i].media_id, i);
        }
    }

    auto rebuild_repository_indices(LocalMediaRepository& repository) -> void
    {
        rebuild_record_index(repository);
        rebuild_blob_index(repository);
        rebuild_thumbnail_index(repository);
    }

    auto insert_record_index(LocalMediaRepository& repository, std::string media_id, std::size_t index) -> void
    {
        repository.record_index.emplace(std::move(media_id), index);
    }

    auto ensure_record_index(LocalMediaRepository& repository) -> void
    {
        if (repository.record_index.size() != repository.records.size())
        {
            rebuild_record_index(repository);
        }
    }

    // The blob index and counts describe the blobs while they were built for exactly this many rows and the index
    // holds exactly the live ones; otherwise the blobs changed behind the repository's back and they are rebuilt.
    auto ensure_blob_index(LocalMediaRepository& repository) -> void
    {
        if (repository.blob_counts_basis != repository.blobs.size() ||
            repository.blob_index.size() != repository.live_blob_total)
        {
            rebuild_blob_index(repository);
        }
    }

    auto ensure_thumbnail_index(LocalMediaRepository& repository) -> void
    {
        if (repository.thumbnail_index.size() != repository.thumbnails.size())
        {
            rebuild_thumbnail_index(repository);
        }
    }

    // Adds a blob that holds a reference. Returns it; the pointer holds until the next change to the blobs.
    auto add_blob_row(LocalMediaRepository& repository, LocalMediaBlob blob) -> LocalMediaBlob*
    {
        ensure_blob_index(repository);
        repository.blob_index.emplace(blob.storage_id, repository.blobs.size());
        ++repository.live_blob_total;
        repository.live_blob_bytes += blob.size_bytes;
        repository.blobs.push_back(std::move(blob));
        repository.blob_counts_basis = repository.blobs.size();
        return &repository.blobs.back();
    }

    // Deletes the row of a blob whose last reference was just released (ADR-0636): the last row moves into its place.
    auto erase_blob_row(LocalMediaRepository& repository, std::string_view storage_id) -> void
    {
        ensure_blob_index(repository);
        auto const found = repository.blob_index.find(std::string{storage_id});
        if (found == repository.blob_index.end() || found->second >= repository.blobs.size())
        {
            return;
        }
        auto const position = found->second;
        repository.blob_index.erase(found);
        --repository.live_blob_total;
        repository.live_blob_bytes -= repository.blobs[position].size_bytes;
        auto const last = repository.blobs.size() - 1U;
        if (position != last)
        {
            repository.blobs[position] = std::move(repository.blobs[last]);
            repository.blob_index[repository.blobs[position].storage_id] = position;
        }
        repository.blobs.pop_back();
        repository.blob_counts_basis = repository.blobs.size();
        repository.media_rows_examined.add(1U);
    }

    // Gives back one reference to the blob; its row goes with the last one.
    auto release_blob_reference(LocalMediaRepository& repository, std::string_view storage_id) -> void
    {
        auto* const blob = find_blob(repository, storage_id);
        if (blob == nullptr)
        {
            return;
        }
        if (--blob->ref_count == 0U)
        {
            erase_blob_row(repository, storage_id);
        }
    }

    // F-46, ADR-0340: a record holds a slot of its owner's record share while
    // it is a live local record. Cached remote media (ADR-0120) never does, and
    // a removed record no longer does; it still counts against the server-wide
    // cap, which is the memory bound.
    [[nodiscard]] auto holds_owner_slot(LocalMediaRecord const& record) noexcept -> bool
    {
        return !record.from_remote_fetch && record.state != LocalMediaState::removed;
    }

    // Counts a live local record into every count kept beside the records. Does not touch the records.
    auto count_record_in(LocalMediaRepository& repository, LocalMediaRecord const& record) -> void
    {
        if (!record.from_remote_fetch)
        {
            ++repository.local_record_total;
        }
        if (holds_owner_slot(record))
        {
            ++repository.owner_record_counts[record.owner_user_id];
            repository.owner_live_bytes[record.owner_user_id] += record.size_bytes;
            if (++repository.local_holders[record.storage_id] == 1U)
            {
                repository.local_held_bytes += record.size_bytes;
            }
        }
    }

    // Rebuilds every record-derived count. Costs the records once.
    auto rebuild_owner_record_counts(LocalMediaRepository& repository) -> void
    {
        repository.media_rows_examined.add(repository.records.size());
        repository.owner_record_counts.clear();
        repository.owner_live_bytes.clear();
        repository.local_holders.clear();
        repository.local_record_total = 0U;
        repository.local_held_bytes = 0U;
        for (auto const& record : repository.records)
        {
            count_record_in(repository, record);
        }
        repository.owner_record_counts_basis = repository.records.size();
    }

    // The counts follow every change this file makes to the records. A record
    // list that changed size behind the repository's back (a restore, a test)
    // is caught here and rebuilt.
    auto ensure_owner_record_counts(LocalMediaRepository& repository) -> void
    {
        if (repository.owner_record_counts_basis != repository.records.size())
        {
            rebuild_owner_record_counts(repository);
        }
    }

    [[nodiscard]] auto owner_record_count(LocalMediaRepository& repository, std::string_view owner_user_id)
        -> std::uint64_t
    {
        ensure_owner_record_counts(repository);
        auto const found = repository.owner_record_counts.find(std::string{owner_user_id});
        return found == repository.owner_record_counts.end() ? std::uint64_t{0U} : found->second;
    }

    // Gives back what `record` holds as a live local record: its owner's slot and bytes and its hold on its stored
    // file. Call before the record is erased or marked removed.
    auto release_local_hold(LocalMediaRepository& repository, LocalMediaRecord const& record) -> void
    {
        ensure_owner_record_counts(repository);
        if (!holds_owner_slot(record))
        {
            return;
        }
        if (auto const found = repository.owner_record_counts.find(record.owner_user_id);
            found != repository.owner_record_counts.end())
        {
            --found->second;
            if (found->second == 0U)
            {
                repository.owner_record_counts.erase(found);
            }
        }
        if (auto const found = repository.owner_live_bytes.find(record.owner_user_id);
            found != repository.owner_live_bytes.end())
        {
            found->second -= std::min(found->second, record.size_bytes);
            if (found->second == 0U)
            {
                repository.owner_live_bytes.erase(found);
            }
        }
        if (auto const found = repository.local_holders.find(record.storage_id);
            found != repository.local_holders.end())
        {
            --found->second;
            if (found->second == 0U)
            {
                repository.local_holders.erase(found);
                repository.local_held_bytes -= std::min(repository.local_held_bytes, record.size_bytes);
            }
        }
    }

    // Removes the thumbnail entry of `media_id`: the last entry moves into its place.
    auto erase_thumbnail(LocalMediaRepository& repository, std::string const& media_id) -> void
    {
        ensure_thumbnail_index(repository);
        auto const found = repository.thumbnail_index.find(media_id);
        if (found == repository.thumbnail_index.end() || found->second >= repository.thumbnails.size())
        {
            return;
        }
        auto const position = found->second;
        repository.thumbnail_index.erase(found);
        auto const last = repository.thumbnails.size() - 1U;
        if (position != last)
        {
            repository.thumbnails[position] = std::move(repository.thumbnails[last]);
            repository.thumbnail_index[repository.thumbnails[position].media_id] = position;
        }
        repository.thumbnails.pop_back();
        repository.media_rows_examined.add(1U);
    }

    // Removes a record, its thumbnail entry and its blob reference. Shared by
    // the upload rollback and by remote-media cache displacement. The last record moves into the erased one's place
    // and its index entry is patched (ADR-0633). A removed record gave its reference back when it was removed
    // (remove_local_media), so it gives back none now (ADR-0636).
    auto erase_record_and_release_blob(LocalMediaRepository& repository, std::string_view media_id) -> bool
    {
        ensure_record_index(repository);
        ensure_owner_record_counts(repository);
        auto const id = std::string{media_id};
        auto const found = repository.record_index.find(id);
        if (found == repository.record_index.end() || found->second >= repository.records.size())
        {
            return false;
        }
        auto const position = found->second;
        auto const& record = repository.records[position];
        auto const storage_id = record.storage_id;
        auto const holds_reference = record.state != LocalMediaState::removed;
        release_local_hold(repository, record);
        if (!record.from_remote_fetch)
        {
            --repository.local_record_total;
        }
        erase_thumbnail(repository, id);
        repository.record_index.erase(id);
        auto const last = repository.records.size() - 1U;
        if (position != last)
        {
            repository.records[position] = std::move(repository.records[last]);
            repository.record_index[repository.records[position].media_id] = position;
        }
        repository.records.pop_back();
        repository.owner_record_counts_basis = repository.records.size();
        repository.media_rows_examined.add(1U);
        if (holds_reference)
        {
            release_blob_reference(repository, storage_id);
        }
        refresh_storage_metrics(repository);
        return true;
    }

    // M05: media IDs must be unpredictable. 16 bytes (128 bits) of CSPRNG
    // output, encoded with URL-safe base64 (no padding), gives 22 characters
    // from the allowed set A-Z a-z 0-9 - _. A fresh ID is checked against the
    // repository to rule out the astronomically unlikely collision.
    [[nodiscard]] auto make_media_id(LocalMediaRepository& repository) -> std::string
    {
        auto constexpr random_bytes = std::size_t{16U};
        auto constexpr max_attempts = std::size_t{10U};

        for (auto attempt = std::size_t{0U}; attempt < max_attempts; ++attempt)
        {
            auto const bytes = crypto::secure_random_bytes(random_bytes);
            if (!bytes.has_value())
            {
                continue;
            }
            auto const encoded = crypto::base64_urlsafe_encode(
                std::string_view{reinterpret_cast<char const*>(bytes->data()), bytes->size()});
            if (!encoded.has_value())
            {
                continue;
            }
            if (!media_id_is_safe(*encoded))
            {
                continue;
            }
            // ADR-0212: a reserved ID is taken even though no record holds it yet.
            if (find_record(repository, *encoded) != nullptr || repository.pending_uploads.contains(*encoded))
            {
                continue;
            }
            return *encoded;
        }
        return {};
    }

    [[nodiscard]] auto make_storage_id(std::string_view digest, std::uint64_t size_bytes) -> std::string
    {
        return "blob_" + std::string{digest} + "_" + std::to_string(size_bytes);
    }

    // Saturating multiply for decode budgets (#429): with extreme operator
    // config (e.g. a 1 TiB upload cap and ratio 64) the product would wrap
    // uint64_t to a small value and silently collapse the budget check.
    [[nodiscard]] auto saturating_scale(std::uint64_t value, std::uint64_t ratio) noexcept -> std::uint64_t
    {
        if (ratio != 0U && value > std::numeric_limits<std::uint64_t>::max() / ratio)
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return value * ratio;
    }

    [[nodiscard]] auto decoder_policy(RuntimeMediaConfig const& config) -> DecoderSafetyPolicy
    {
        auto const max_input =
            config.max_decode_input_bytes == 0U ? config.max_upload_bytes : config.max_decode_input_bytes;
        auto const max_output = config.max_decode_output_bytes == 0U
                                    ? saturating_scale(config.max_upload_bytes, config.max_decompression_ratio)
                                    : config.max_decode_output_bytes;
        return {max_input,
                max_output,
                config.max_decode_pixels,
                static_cast<std::uint32_t>(config.max_animation_frames),
                static_cast<std::uint32_t>(config.max_decompression_ratio),
                true};
    }

    [[nodiscard]] auto decoder_request(RuntimeMediaConfig const& config, std::uint64_t size_bytes,
                                       std::uint64_t decoded_size_bytes, std::uint64_t pixel_count,
                                       std::uint64_t animation_frame_count, bool decoder_marked_safe)
        -> DecoderSafetyRequest
    {
        auto const output_bytes = decoded_size_bytes == 0U ? size_bytes : decoded_size_bytes;
        auto const pixels =
            pixel_count == 0U ? std::min<std::uint64_t>(size_bytes, config.max_decode_pixels) : pixel_count;
        return {size_bytes, output_bytes, pixels, static_cast<std::uint32_t>(animation_frame_count),
                decoder_marked_safe};
    }

    [[nodiscard]] auto worker_plan(RuntimeMediaConfig const& config) -> SandboxedMediaWorkerPlan
    {
        auto plan = SandboxedMediaWorkerPlan{};
        plan.dedicated_worker = config.decode_in_sandbox;
        plan.network_disabled = true;
        plan.read_only_root = true;
        plan.private_tmp = true;
        plan.seccomp_required = true;
        plan.decode_timeout_seconds = 10U;
        if (config.max_decode_output_bytes == 0U)
        {
            auto const scaled = saturating_scale(config.max_upload_bytes, 64U);
            plan.memory_limit_bytes = std::max<std::uint64_t>(268435456U, scaled);
        }
        else
        {
            plan.memory_limit_bytes = config.max_decode_output_bytes;
        }
        return plan;
    }

    [[nodiscard]] auto processing_rejection_status(std::string_view reason) noexcept -> std::uint16_t
    {
        if (reason.find("limit") != std::string_view::npos || reason.find("exceeds") != std::string_view::npos ||
            reason.find("dimensions") != std::string_view::npos || reason.find("expansion") != std::string_view::npos)
        {
            return 413U;
        }
        return 400U;
    }

    [[nodiscard]] auto content_type_is_thumbnailable(std::string_view content_type) noexcept -> bool
    {
        // A spelling variant of a type ("img/png", media_types_are_equivalent) is that type.
        return media_types_are_equivalent(content_type, "image/png") ||
               media_types_are_equivalent(content_type, "image/jpeg") ||
               media_types_are_equivalent(content_type, "image/gif");
    }

    auto record_thumbnail(LocalMediaRepository& repository, LocalMediaRecord const& record) -> void
    {
        if (!repository.config.thumbnailing_enabled || !content_type_is_thumbnailable(record.content_type) ||
            record.state != LocalMediaState::available)
        {
            return;
        }
        // Registers the media as thumbnailable. Dimensions are intentionally left
        // 0×0: thumbnails are not produced at ingest. They are generated on demand
        // by the sandboxed out-of-process worker (see media/Thumbnailer.hpp and
        // download_local_media_thumbnail), which decodes the original blob and
        // resamples to the requested geometry. This entry simply records that the
        // source is a resamplable image type.
        ensure_thumbnail_index(repository);
        repository.thumbnail_index.emplace(record.media_id, repository.thumbnails.size());
        repository.thumbnails.push_back(
            {record.media_id, record.storage_id, 0U, 0U, record.content_type, record.size_bytes});
        ++repository.metrics.thumbnails_generated;
    }

    [[nodiscard]] auto upload_rejection_status(std::string_view reason) noexcept -> std::uint16_t
    {
        if (reason == "media upload exceeds size limit")
        {
            return 413U;
        }
        if (reason == "media MIME type is not allowed")
        {
            return 415U;
        }
        return 400U;
    }

    // Repository capacity accounting (0.12.5 audit, finding 19).
    //
    // Bytes are counted over live *blobs*, not records: two records that
    // deduplicate onto one blob occupy one blob's worth of memory, so charging
    // both would refuse uploads long before the repository was actually full.

    // ADR-0120: remote media is accounted against the remote media cache's own budget, never against local quotas,
    // so cached remote files cannot make a local upload fail. A record says where it came from (from_remote_fetch);
    // the owner string is not trusted for this (security audit run-1).
    // Bytes of local media, counting each stored file once however many local
    // records share it. A record's size is its blob's size.
    // The four readers below answer from counts kept as records change (ADR-0633), so an upload under
    // runtime.mutex does not scan the records.
    [[nodiscard]] auto local_media_bytes(LocalMediaRepository& repository) -> std::uint64_t
    {
        ensure_owner_record_counts(repository);
        return repository.local_held_bytes;
    }

    [[nodiscard]] auto local_media_holds(LocalMediaRepository& repository, std::string_view storage_id) -> bool
    {
        ensure_owner_record_counts(repository);
        return repository.local_holders.contains(std::string{storage_id});
    }

    [[nodiscard]] auto local_record_count(LocalMediaRepository& repository) -> std::uint64_t
    {
        ensure_owner_record_counts(repository);
        return repository.local_record_total;
    }

    [[nodiscard]] auto live_bytes_for_owner(LocalMediaRepository& repository, std::string_view owner_user_id)
        -> std::uint64_t
    {
        ensure_owner_record_counts(repository);
        auto const found = repository.owner_live_bytes.find(std::string{owner_user_id});
        return found == repository.owner_live_bytes.end() ? std::uint64_t{0U} : found->second;
    }

    // Which capacity limit, if any, this upload would cross. Empty means it fits. The per-user byte quota is charged
    // for every upload, deduplicated or not: whether it passes must not depend on what other users hold (C42,
    // ADR-0689).
    [[nodiscard]] auto capacity_rejection_reason(LocalMediaRepository& repository,
                                                 LocalMediaUploadRequest const& request, std::uint64_t size_bytes,
                                                 std::string_view storage_id) -> std::string
    {
        auto const& limits = repository.config;
        if (request.from_remote_fetch)
        {
            // ADR-0120: the remote cache makes room by evicting least recently
            // used files (plan_remote_media_admission), so the only refusal is a
            // single file larger than the whole remote budget.
            if (limits.remote_media_cache_max_bytes != 0U && size_bytes > limits.remote_media_cache_max_bytes)
            {
                return "remote media is larger than the remote media cache";
            }
            return {};
        }
        if (limits.max_records != 0U && local_record_count(repository) >= limits.max_records)
        {
            return "media repository record limit reached";
        }
        // F-46, ADR-0340: one owner's share of the records, charged for a
        // deduplicated upload too, which adds a record but no bytes.
        if (limits.max_records_per_user != 0U &&
            owner_record_count(repository, request.owner_user_id) >= limits.max_records_per_user)
        {
            return "media record quota for this user is exhausted";
        }
        // A file already held for local media adds nothing; one held only for
        // cached remote media becomes local usage now.
        if (limits.max_total_bytes != 0U && !local_media_holds(repository, storage_id) &&
            local_media_bytes(repository) + size_bytes > limits.max_total_bytes)
        {
            return "media repository storage limit reached";
        }
        if (limits.max_bytes_per_user != 0U &&
            live_bytes_for_owner(repository, request.owner_user_id) + size_bytes > limits.max_bytes_per_user)
        {
            return "media quota for this user is exhausted";
        }
        return {};
    }

    [[nodiscard]] auto make_metric(std::string name, std::uint64_t value) -> observability::MetricSample
    {
        return {std::move(name), static_cast<std::int64_t>(value), true};
    }

} // namespace

auto local_media_state_name(LocalMediaState state) noexcept -> char const*
{
    switch (state)
    {
    case LocalMediaState::available:
        return "available";
    case LocalMediaState::quarantined:
        return "quarantined";
    case LocalMediaState::removed:
        return "removed";
    }

    return "unknown";
}

auto is_remote_cache_owner(std::string_view owner_user_id, std::string_view local_server_name) noexcept -> bool
{
    constexpr auto prefix = std::string_view{"@remote-media:"};
    if (!owner_user_id.starts_with(prefix))
    {
        return false;
    }
    // The prefix ends at the first ':', so the rest is the owner's server name.
    auto const origin = owner_user_id.substr(prefix.size());
    return !origin.empty() && origin != local_server_name;
}

auto make_local_media_repository(RuntimeMediaConfig config) -> LocalMediaRepository
{
    auto repository = LocalMediaRepository{};
    repository.config = std::move(config);
    refresh_storage_metrics(repository);
    return repository;
}

auto make_local_media_storage_id(std::string_view digest, std::uint64_t size_bytes) -> std::string
{
    return make_storage_id(digest, size_bytes);
}

auto calculate_media_digest(std::string_view bytes) -> std::string
{
    auto const digest = crypto::hash_bytes_to_hex(bytes);
    return digest.value_or("");
}

auto media_repository_summary(LocalMediaRepository const& repository) -> std::string
{
    return "Media repository: records=" + std::to_string(repository.records.size()) +
           " blobs=" + std::to_string(repository.metrics.stored_blobs) +
           " stored_bytes=" + std::to_string(repository.metrics.stored_bytes) +
           " remote_fetch_enabled=" + std::string{repository.config.remote_fetch_enabled ? "true" : "false"};
}

auto media_repository_metrics(LocalMediaRepository const& repository) -> std::vector<observability::MetricSample>
{
    return {
        make_metric("media_uploads_accepted_total", repository.metrics.uploads_accepted),
        make_metric("media_uploads_rejected_total", repository.metrics.uploads_rejected),
        make_metric("media_uploads_quarantined_total", repository.metrics.uploads_quarantined),
        make_metric("media_downloads_served_total", repository.metrics.downloads_served),
        make_metric("media_downloads_blocked_total", repository.metrics.downloads_blocked),
        make_metric("media_deduplicated_uploads_total", repository.metrics.deduplicated_uploads),
        make_metric("media_admin_quarantines_total", repository.metrics.admin_quarantines),
        make_metric("media_admin_releases_total", repository.metrics.admin_releases),
        make_metric("media_admin_removals_total", repository.metrics.admin_removals),
        make_metric("media_remote_fetch_rejections_total", repository.metrics.remote_fetch_rejections),
        make_metric("media_remote_fetches_accepted_total", repository.metrics.remote_fetches_accepted),
        make_metric("media_processing_rejections_total", repository.metrics.processing_rejections),
        make_metric("media_thumbnails_generated_total", repository.metrics.thumbnails_generated),
        make_metric("media_thumbnails_served_total", repository.metrics.thumbnails_served),
        make_metric("media_stored_blobs", repository.metrics.stored_blobs),
        make_metric("media_stored_bytes", repository.metrics.stored_bytes),
    };
}

auto find_local_media_record(LocalMediaRepository& repository, std::string_view media_id) noexcept
    -> LocalMediaRecord const*
{
    ensure_record_index(repository);
    auto const iterator = repository.record_index.find(std::string{media_id});
    if (iterator == repository.record_index.end())
    {
        return nullptr;
    }
    if (iterator->second >= repository.records.size())
    {
        return nullptr;
    }
    return &repository.records[iterator->second];
}

auto find_local_media_blob(LocalMediaRepository& repository, std::string_view storage_id) noexcept
    -> LocalMediaBlob const*
{
    ensure_blob_index(repository);
    auto const iterator = repository.blob_index.find(std::string{storage_id});
    if (iterator == repository.blob_index.end())
    {
        return nullptr;
    }
    if (iterator->second >= repository.blobs.size() || repository.blobs[iterator->second].ref_count == 0U)
    {
        return nullptr;
    }
    return &repository.blobs[iterator->second];
}

auto find_local_media_thumbnail(LocalMediaRepository const& repository, std::string_view media_id) noexcept
    -> LocalMediaThumbnail const*
{
    if (repository.thumbnail_index.size() == repository.thumbnails.size())
    {
        auto const found = repository.thumbnail_index.find(std::string{media_id});
        if (found != repository.thumbnail_index.end() && found->second < repository.thumbnails.size() &&
            repository.thumbnails[found->second].media_id == media_id)
        {
            return &repository.thumbnails[found->second];
        }
        return nullptr;
    }
    repository.media_rows_examined.add(repository.thumbnails.size());
    auto const iterator = std::ranges::find_if(repository.thumbnails, [media_id](LocalMediaThumbnail const& thumb) {
        return thumb.media_id == media_id;
    });
    return iterator == repository.thumbnails.end() ? nullptr : &(*iterator);
}

auto restore_local_media_repository(LocalMediaRepository& repository, std::vector<LocalMediaRecord> records,
                                    std::vector<LocalMediaBlob> blobs) -> void
{
    clear_repository_indices(repository);
    repository.remote_media_cache.clear();
    repository.records = std::move(records);
    // ADR-0636: a row at zero references is not live; earlier versions left some in the database.
    std::erase_if(blobs, [](LocalMediaBlob const& blob) {
        return blob.ref_count == 0U;
    });
    repository.blobs = std::move(blobs);
    repository.thumbnails.clear();
    for (auto const& record : repository.records)
    {
        record_thumbnail(repository, record);
    }
    rebuild_repository_indices(repository);
    rebuild_owner_record_counts(repository);
    refresh_storage_metrics(repository);
}

auto upload_local_media(LocalMediaRepository& repository, std::string_view server_name,
                        LocalMediaUploadRequest const& request) -> LocalMediaUploadResult
{
    auto const digest = calculate_media_digest(request.bytes);
    auto const size_bytes = static_cast<std::uint64_t>(request.bytes.size());
    auto const content_type = canonical_content_type(request);
    log_diagnostic("upload.dispatch", {
                                          {"owner",        request.owner_user_id,      false},
                                          {"size_bytes",   std::to_string(size_bytes), false},
                                          {"content_type", content_type,               false}
    });
    if (digest.empty())
    {
        ++repository.metrics.uploads_rejected;
        log_diagnostic("upload.rejected",
                       {
                           {"owner",  request.owner_user_id,       false},
                           {"reason", "digest calculation failed", false}
        });
        return {false,
                500U,
                {},
                {},
                content_type,
                size_bytes,
                "blake2b",
                {},
                false,
                false,
                "media digest calculation failed"};
    }
    auto const scanner_clean = repository.config.enable_av_scanner ? request.scanner_clean : true;
    auto const decision = evaluate_media_upload(
        upload_policy(repository.config, request.from_remote_fetch),
        {size_bytes, request.declared_mime_type, request.sniffed_mime_type, digest, scanner_clean});

    if (decision.disposition == MediaDisposition::reject)
    {
        ++repository.metrics.uploads_rejected;
        log_diagnostic("upload.rejected",
                       {
                           {"owner",  request.owner_user_id, false},
                           {"reason", decision.reason,       false}
        });
        return {false,
                upload_rejection_status(decision.reason),
                {},
                {},
                {},
                size_bytes,
                "blake2b",
                digest,
                false,
                false,
                decision.reason};
    }
    if (!sandboxed_worker_plan_is_hardened(worker_plan(repository.config)))
    {
        ++repository.metrics.processing_rejections;
        return {false,
                500U,
                {},
                {},
                content_type,
                size_bytes,
                "blake2b",
                digest,
                false,
                false,
                "media processing worker is not sandboxed"};
    }
    auto const decoder_decision = evaluate_decoder_safety(
        decoder_policy(repository.config),
        decoder_request(repository.config, size_bytes, request.decoded_size_bytes, request.pixel_count,
                        request.animation_frame_count, request.decoder_marked_safe));
    if (decoder_decision.disposition == MediaDisposition::reject)
    {
        ++repository.metrics.processing_rejections;
        return {false,
                processing_rejection_status(decoder_decision.reason),
                {},
                {},
                content_type,
                size_bytes,
                "blake2b",
                digest,
                false,
                false,
                decoder_decision.reason};
    }

    // ADR-0212: content for a reserved ID may be stored only once.
    if (!request.media_id.empty() &&
        (!media_id_is_safe(request.media_id) || find_record(repository, request.media_id) != nullptr))
    {
        ++repository.metrics.uploads_rejected;
        return {
            false, 409U, {}, {}, content_type, size_bytes, "blake2b", digest, false, false, "media already uploaded"};
    }

    // 0.12.5 audit, finding 19: refuse before storing anything. Refusing rather
    // than evicting is deliberate — a client already holds an mxc:// URI for
    // everything in here, so dropping the oldest blob would silently break
    // existing links rather than shed load.
    auto deduplicated = false;
    auto* blob = find_live_blob(repository, "blake2b", digest, size_bytes);
    if (auto const capacity_reason =
            capacity_rejection_reason(repository, request, size_bytes, make_storage_id(digest, size_bytes));
        !capacity_reason.empty())
    {
        ++repository.metrics.uploads_rejected;
        log_diagnostic("upload.rejected",
                       {
                           {"owner",  request.owner_user_id, false},
                           {"reason", capacity_reason,       false}
        });
        return {false, 507U, {}, {}, content_type, size_bytes, "blake2b", digest, false, false, capacity_reason};
    }
    if (blob == nullptr)
    {
        auto new_blob = LocalMediaBlob{};
        new_blob.storage_id = make_storage_id(digest, size_bytes);
        new_blob.hash_algorithm = "blake2b";
        new_blob.digest = digest;
        new_blob.size_bytes = size_bytes;
        new_blob.ref_count = 1U;
        // Storage IDs are durable primary keys, and a row exists only while it has a reference (ADR-0636), so no
        // row with this identity is held here.
        blob = add_blob_row(repository, std::move(new_blob));
    }
    else
    {
        ++blob->ref_count;
        deduplicated = true;
        ++repository.metrics.deduplicated_uploads;
    }

    auto record = LocalMediaRecord{};
    record.media_id = request.media_id.empty() ? make_media_id(repository) : request.media_id;
    if (record.media_id.empty())
    {
        // This is only reachable if the CSPRNG or base64 encoder failed
        // repeatedly. Roll back the blob reference we just added.
        release_blob_reference(repository, std::string{blob->storage_id});
        ++repository.metrics.uploads_rejected;
        log_diagnostic("upload.rejected",
                       {
                           {"owner",  request.owner_user_id,        false},
                           {"reason", "media id generation failed", false}
        });
        return {false,
                500U,
                {},
                {},
                content_type,
                size_bytes,
                "blake2b",
                digest,
                false,
                false,
                "media id generation failed"};
    }
    record.owner_user_id = request.owner_user_id;
    record.from_remote_fetch = request.from_remote_fetch;
    record.content_type = content_type;
    record.size_bytes = size_bytes;
    record.hash_algorithm = "blake2b";
    record.digest = digest;
    record.storage_id = blob->storage_id;
    record.state = decision.disposition == MediaDisposition::quarantine ? LocalMediaState::quarantined
                                                                        : LocalMediaState::available;
    record.quarantine_reason = decision.reason;
    // New uploads are invisible to the legacy unauthenticated endpoints.
    record.legacy_endpoint_visible = false;
    record.upload_name = media_filename_is_valid(request.upload_name) ? request.upload_name : std::string{};
    auto const media_id = record.media_id;
    auto const record_index = repository.records.size();
    ensure_owner_record_counts(repository);
    count_record_in(repository, record);
    repository.records.push_back(std::move(record));
    repository.owner_record_counts_basis = repository.records.size();
    insert_record_index(repository, media_id, record_index);
    record_thumbnail(repository, repository.records.back());

    ++repository.metrics.uploads_accepted;
    auto const quarantined = decision.disposition == MediaDisposition::quarantine;
    if (quarantined)
    {
        ++repository.metrics.uploads_quarantined;
    }
    refresh_storage_metrics(repository);
    log_diagnostic("upload.accepted", {
                                          {"owner",        request.owner_user_id,           false},
                                          {"media_id",     media_id,                        false},
                                          {"size_bytes",   std::to_string(size_bytes),      false},
                                          {"deduplicated", deduplicated ? "true" : "false", false},
                                          {"quarantined",  quarantined ? "true" : "false",  false}
    });
    return {
        true,
        static_cast<std::uint16_t>(quarantined ? 202U : 200U),
        media_id,
        "mxc://" + std::string{server_name} + "/" + media_id,
        content_type,
        size_bytes,
        "blake2b",
        digest,
        deduplicated,
        quarantined,
        decision.reason,
    };
}

auto rollback_local_media_upload(LocalMediaRepository& repository, std::string_view media_id) -> bool
{
    auto const* record = find_local_media_record(repository, media_id);
    if (record == nullptr)
    {
        return false;
    }
    auto const quarantined = record->state == LocalMediaState::quarantined;
    if (auto const* blob = find_blob(repository, record->storage_id);
        blob != nullptr && blob->ref_count > 1U && repository.metrics.deduplicated_uploads > 0U)
    {
        --repository.metrics.deduplicated_uploads;
    }
    std::ignore = erase_record_and_release_blob(repository, media_id);
    if (repository.metrics.uploads_accepted > 0U)
    {
        --repository.metrics.uploads_accepted;
    }
    if (quarantined && repository.metrics.uploads_quarantined > 0U)
    {
        --repository.metrics.uploads_quarantined;
    }
    ++repository.metrics.uploads_rejected;
    return true;
}

auto plan_pending_media_upload(LocalMediaRepository& repository, std::string_view owner_user_id, std::uint64_t now_ms)
    -> PendingMediaUploadPlan
{
    auto plan = PendingMediaUploadPlan{};
    auto live_total = std::uint64_t{0U};
    auto live_for_owner = std::uint64_t{0U};
    // One pass, linear in the reservations held. An expired reservation counts toward no quota; at most
    // max_expired_reservations_swept_per_create of them are listed for deletion (F-16).
    repository.pending_rows_examined.add(repository.pending_uploads.size());
    for (auto const& [media_id, reservation] : repository.pending_uploads)
    {
        if (reservation.expires_at_ms <= now_ms)
        {
            if (plan.expired_media_ids.size() < max_expired_reservations_swept_per_create)
            {
                plan.expired_media_ids.push_back(media_id);
            }
            continue;
        }
        ++live_total;
        if (reservation.owner_user_id == owner_user_id)
        {
            ++live_for_owner;
        }
    }
    auto const& config = repository.config;
    if (live_for_owner >= std::max<std::uint64_t>(config.max_pending_uploads_per_user, 1U))
    {
        plan.status = 429U;
        plan.reason = "too many pending media uploads";
        return plan;
    }
    if (live_total >= std::max<std::uint64_t>(config.max_pending_uploads, 1U))
    {
        plan.status = 429U;
        plan.reason = "too many pending media uploads on this server";
        return plan;
    }
    auto media_id = make_media_id(repository);
    if (media_id.empty())
    {
        plan.status = 500U;
        plan.reason = "media id generation failed";
        return plan;
    }
    auto const ttl_ms = std::max<std::uint64_t>(config.pending_upload_ttl_ms, 1U);
    plan.ok = true;
    plan.status = 200U;
    plan.reservation = {std::move(media_id), std::string{owner_user_id}, now_ms, now_ms + ttl_ms};
    return plan;
}

auto apply_pending_media_upload(LocalMediaRepository& repository, PendingMediaUploadPlan const& plan) -> void
{
    repository.pending_rows_examined.add(plan.expired_media_ids.size());
    for (auto const& expired : plan.expired_media_ids)
    {
        repository.pending_uploads.erase(expired);
    }
    if (plan.ok)
    {
        repository.pending_uploads.insert_or_assign(plan.reservation.media_id, plan.reservation);
    }
}

auto restore_pending_media_uploads(LocalMediaRepository& repository, std::vector<PendingMediaUpload> reservations)
    -> void
{
    repository.pending_uploads.clear();
    for (auto& reservation : reservations)
    {
        // A reservation whose content is already stored was completed; the
        // record wins.
        if (find_record(repository, reservation.media_id) == nullptr && media_id_is_safe(reservation.media_id))
        {
            auto key = reservation.media_id;
            repository.pending_uploads.insert_or_assign(std::move(key), std::move(reservation));
        }
    }
}

auto find_pending_media_upload(LocalMediaRepository const& repository, std::string_view media_id,
                               std::uint64_t now_ms) noexcept -> PendingMediaUpload const*
{
    auto const found = repository.pending_uploads.find(std::string{media_id});
    if (found == repository.pending_uploads.end() || found->second.expires_at_ms <= now_ms)
    {
        return nullptr;
    }
    return &found->second;
}

auto admit_pending_media_upload(LocalMediaRepository& repository, std::string_view media_id, std::string_view user_id,
                                std::uint64_t now_ms) -> PendingUploadAdmission
{
    if (!media_id_is_safe(media_id))
    {
        return PendingUploadAdmission::not_found;
    }
    if (auto const* record = find_record(repository, media_id); record != nullptr)
    {
        // Content is already there. Only its uploader learns that; to anyone
        // else this is someone else's media ID.
        return record->owner_user_id == user_id && !record->from_remote_fetch ? PendingUploadAdmission::already_uploaded
                                                                              : PendingUploadAdmission::forbidden;
    }
    auto const* reservation = find_pending_media_upload(repository, media_id, now_ms);
    if (reservation == nullptr)
    {
        return PendingUploadAdmission::not_found;
    }
    return reservation->owner_user_id == user_id ? PendingUploadAdmission::accepted : PendingUploadAdmission::forbidden;
}

auto complete_pending_media_upload(LocalMediaRepository& repository, std::string_view media_id) -> void
{
    repository.pending_uploads.erase(std::string{media_id});
}

auto resolve_local_media_download(LocalMediaRepository& repository, std::string_view media_id, bool legacy_endpoint)
    -> LocalMediaDownloadTarget
{
    log_diagnostic("download.dispatch", {
                                            {"media_id", std::string{media_id}, false}
    });
    if (!media_id_is_safe(media_id))
    {
        ++repository.metrics.downloads_blocked;
        log_diagnostic("download.rejected",
                       {
                           {"media_id", std::string{media_id}, false},
                           {"reason",   "invalid media id",    false}
        });
        return {false, 400U, {}, {}, "invalid media id"};
    }

    auto const* record = find_local_media_record(repository, media_id);
    if (record == nullptr || record->state == LocalMediaState::removed ||
        (legacy_endpoint && !record->legacy_endpoint_visible))
    {
        ++repository.metrics.downloads_blocked;
        log_diagnostic("download.rejected",
                       {
                           {"media_id", std::string{media_id}, false},
                           {"reason",   "media not found",     false}
        });
        return {false, 404U, {}, {}, "media not found"};
    }
    if (record->state == LocalMediaState::quarantined)
    {
        ++repository.metrics.downloads_blocked;
        log_diagnostic("download.rejected",
                       {
                           {"media_id", std::string{media_id},  false},
                           {"reason",   "media is quarantined", false}
        });
        return {false, 451U, {}, {}, "media is quarantined"};
    }

    if (find_blob(repository, record->storage_id) == nullptr)
    {
        ++repository.metrics.downloads_blocked;
        log_diagnostic("download.rejected",
                       {
                           {"media_id", std::string{media_id}, false},
                           {"reason",   "blob missing",        false}
        });
        return {false, 500U, {}, {}, "media blob missing"};
    }

    ++repository.metrics.downloads_served;
    log_diagnostic("download.accepted", {
                                            {"media_id",     std::string{media_id},              false},
                                            {"content_type", record->content_type,               false},
                                            {"size_bytes",   std::to_string(record->size_bytes), false}
    });
    return {true, 200U, record->content_type, record->storage_id, {}};
}

auto local_media_still_servable(LocalMediaRepository& repository, std::string_view media_id,
                                std::string_view storage_id, bool legacy_endpoint) -> bool
{
    auto const* record = find_local_media_record(repository, media_id);
    return record != nullptr && record->state == LocalMediaState::available && record->storage_id == storage_id &&
           (!legacy_endpoint || record->legacy_endpoint_visible) && find_blob(repository, storage_id) != nullptr;
}

[[nodiscard]] auto make_multipart_boundary() -> std::string
{
    auto const id = crypto::secure_random_hex(16U);
    return id.has_value() ? "mrv_" + *id : "mrv_boundary_fallback";
}

auto build_federation_media_download_body(std::string_view media_content_type, std::string_view bytes,
                                          std::string_view upload_name) -> FederationMediaDownloadBody
{
    auto const canonical_type =
        media_content_type.empty() ? std::string_view{"application/octet-stream"} : media_content_type;
    auto const boundary = make_multipart_boundary();
    // Spec (SS API § Content Repository): 200 response MUST be multipart/mixed
    // with exactly two parts. The first part is application/json metadata
    // (currently always an empty object). The second part carries the media
    // bytes with Content-Type and Content-Disposition headers.
    auto body = std::string{};
    body.reserve(256U + bytes.size());
    body += "--" + boundary + "\r\n";
    body += "Content-Type: application/json\r\n\r\n{}\r\n";
    body += "--" + boundary + "\r\n";
    body += std::string{"Content-Type: "} + std::string{canonical_type} + "\r\n";
    // 0.12.5 audit, finding 8: derive the disposition from the same
    // inline-safe allow-list the client-facing download path uses. This was
    // hardcoded to `inline`, so a peer's clients were told to render an
    // executable or a scripted document inline -- bypassing the allow-list
    // entirely for anything served over federation. Unknown and
    // non-inline-safe types fail closed to `attachment`.
    // R17: the header is written only by media_content_disposition, which picks inline or
    // attachment from the same allow-list and leaves out a filename no header could carry.
    body += "Content-Disposition: " + media_content_disposition(canonical_type, upload_name) + "\r\n\r\n";
    body += std::string{bytes} + "\r\n";
    body += "--" + boundary + "--\r\n";
    return {std::move(body), "multipart/mixed; boundary=" + boundary};
}

auto validate_local_media_admin_action(LocalMediaRepository const& repository, std::string_view media_id,
                                       LocalMediaAdminAction action, std::string_view reason) -> LocalMediaAdminResult
{
    if (!media_id_is_safe(media_id))
    {
        return {false, 400U, {}, LocalMediaState::available, "invalid media id"};
    }

    auto state = LocalMediaState::available;
    auto message = std::string_view{};
    switch (action)
    {
    case LocalMediaAdminAction::quarantine:
        if (reason.empty())
        {
            return {false, 400U, std::string{media_id}, LocalMediaState::available, "quarantine reason is required"};
        }
        state = LocalMediaState::quarantined;
        message = "quarantined";
        break;
    case LocalMediaAdminAction::release:
        message = "released";
        break;
    case LocalMediaAdminAction::remove:
        if (reason.empty())
        {
            return {false, 400U, std::string{media_id}, LocalMediaState::available, "removal reason is required"};
        }
        state = LocalMediaState::removed;
        message = "removed";
        break;
    default:
        return {false, 400U, std::string{media_id}, LocalMediaState::available, "invalid media action"};
    }

    // The index answers while it is in step; a repository whose records changed behind its back is scanned.
    auto const* record = static_cast<LocalMediaRecord const*>(nullptr);
    if (repository.record_index.size() == repository.records.size())
    {
        if (auto const found = repository.record_index.find(std::string{media_id});
            found != repository.record_index.end() && found->second < repository.records.size() &&
            repository.records[found->second].media_id == media_id)
        {
            record = &repository.records[found->second];
        }
    }
    else
    {
        repository.media_rows_examined.add(repository.records.size());
        if (auto const found = std::ranges::find_if(repository.records,
                                                    [media_id](LocalMediaRecord const& current) {
                                                        return current.media_id == media_id;
                                                    });
            found != repository.records.end())
        {
            record = &*found;
        }
    }
    if (record == nullptr || record->state == LocalMediaState::removed)
    {
        return {false, 404U, std::string{media_id}, LocalMediaState::removed, "media not found"};
    }

    return {true, 200U, record->media_id, state, std::string{message}};
}

auto quarantine_local_media(LocalMediaRepository& repository, std::string_view media_id, std::string_view reason)
    -> LocalMediaAdminResult
{
    auto const validation =
        validate_local_media_admin_action(repository, media_id, LocalMediaAdminAction::quarantine, reason);
    if (!validation.ok)
    {
        return validation;
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr)
    {
        return {false, 404U, std::string{media_id}, LocalMediaState::removed, "media not found"};
    }

    record->state = LocalMediaState::quarantined;
    record->quarantine_reason = std::string{reason};
    ++repository.metrics.admin_quarantines;
    log_diagnostic("admin.quarantined",
                   {
                       {"media_id", record->media_id,    false},
                       {"reason",   std::string{reason}, false}
    });
    return {true, 200U, record->media_id, record->state, "quarantined"};
}

auto release_local_media(LocalMediaRepository& repository, std::string_view media_id) -> LocalMediaAdminResult
{
    auto const validation = validate_local_media_admin_action(repository, media_id, LocalMediaAdminAction::release);
    if (!validation.ok)
    {
        return validation;
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr)
    {
        return {false, 404U, std::string{media_id}, LocalMediaState::removed, "media not found"};
    }

    record->state = LocalMediaState::available;
    record->quarantine_reason.clear();
    ++repository.metrics.admin_releases;
    log_diagnostic("admin.released", {
                                         {"media_id", record->media_id, false}
    });
    return {true, 200U, record->media_id, record->state, "released"};
}

auto remove_local_media(LocalMediaRepository& repository, std::string_view media_id, std::string_view reason)
    -> LocalMediaAdminResult
{
    auto const validation =
        validate_local_media_admin_action(repository, media_id, LocalMediaAdminAction::remove, reason);
    if (!validation.ok)
    {
        return validation;
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr)
    {
        return {false, 404U, std::string{media_id}, LocalMediaState::removed, "media not found"};
    }

    auto const storage_id = record->storage_id;
    release_local_hold(repository, *record);
    record->state = LocalMediaState::removed;
    record->quarantine_reason = std::string{reason};
    release_blob_reference(repository, storage_id);

    ++repository.metrics.admin_removals;
    refresh_storage_metrics(repository);
    log_diagnostic("admin.removed", {
                                        {"media_id", record->media_id,    false},
                                        {"reason",   std::string{reason}, false}
    });
    return {true, 200U, record->media_id, record->state, "removed"};
}

namespace
{

    [[nodiscard]] auto remote_media_cache_entry_matches(RemoteMediaCacheEntry const& entry,
                                                        std::string_view origin_server,
                                                        std::string_view media_id) noexcept -> bool
    {
        return entry.origin_server == origin_server && entry.media_id == media_id;
    }

    // The bytes are the ones just fetched, which match the cached record's
    // digest; nothing is read from storage here.
    [[nodiscard]] auto cached_remote_media_result(LocalMediaRepository& repository, LocalMediaRecord const& record,
                                                  std::string const& fetched_bytes) -> RemoteMediaDownloadResult
    {
        ++repository.metrics.downloads_served;
        return {true,
                200U,
                {},
                record.content_type,
                fetched_bytes,
                record.size_bytes,
                record.hash_algorithm,
                record.digest,
                record.storage_id,
                record.media_id,
                false};
    }

} // namespace

auto remote_media_cache_now_ms() noexcept -> std::uint64_t
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

auto find_cached_remote_media(LocalMediaRepository& repository, std::string_view origin_server,
                              std::string_view media_id, std::uint64_t now) -> LocalMediaRecord const*
{
    auto const entry =
        std::ranges::find_if(repository.remote_media_cache, [origin_server, media_id](RemoteMediaCacheEntry const& e) {
            return remote_media_cache_entry_matches(e, origin_server, media_id);
        });
    if (entry == repository.remote_media_cache.end() || entry->expires_at_ms <= now)
    {
        return nullptr;
    }
    auto const* record = find_local_media_record(repository, entry->local_media_id);
    if (record == nullptr)
    {
        // Nothing stored behind it any more: the entry cannot be served or
        // released, so it is dropped.
        repository.remote_media_cache.erase(entry);
        return nullptr;
    }
    auto hit = std::move(*entry);
    hit.last_access_ms = now;
    repository.remote_media_cache.erase(entry);
    repository.remote_media_cache.push_back(std::move(hit));
    return record;
}

auto plan_remote_media_admission(LocalMediaRepository const& repository, std::string_view origin_server,
                                 std::string_view media_id, std::uint64_t incoming_size_bytes, std::uint64_t now_ms)
    -> std::vector<RemoteMediaCacheEntry>
{
    auto displaced = std::vector<RemoteMediaCacheEntry>{};
    auto others = std::vector<RemoteMediaCacheEntry const*>{};
    // Dropping an entry costs a pass over the records, so each admission drops
    // only a few expired entries (oldest first); the rest stay and are still
    // held to the caps by the least-recently-used eviction below.
    constexpr auto max_expired_dropped = std::size_t{16U};
    auto expired_dropped = std::size_t{0U};
    for (auto const& entry : repository.remote_media_cache)
    {
        // An entry past its lifetime is never served (find_cached_remote_media),
        // so it is released now rather than holding a place under the caps.
        auto const expired = entry.expires_at_ms <= now_ms && expired_dropped < max_expired_dropped;
        if (remote_media_cache_entry_matches(entry, origin_server, media_id) || expired)
        {
            expired_dropped += expired ? 1U : 0U;
            displaced.push_back(entry);
        }
        else
        {
            others.push_back(&entry);
        }
    }
    // The cache is kept in recency order, least recently used first, so the
    // entries to evict are at the front: enough to leave room for one more
    // entry and, under the byte budget (ADR-0120), for the incoming file. With
    // an entry cap of 0 every other entry goes.
    auto const max_entries = repository.config.remote_media_cache_max_entries;
    auto const max_bytes = repository.config.remote_media_cache_max_bytes;
    auto const keep = max_entries == 0U ? std::size_t{0U} : static_cast<std::size_t>(max_entries - 1U);
    auto kept_bytes = std::uint64_t{0U};
    // F-47, ADR-0341: each entry carries its own size, so this is one pass over
    // the cache and not one pass over every record per entry.
    for (auto const* entry : others)
    {
        kept_bytes += entry->size_bytes;
    }
    auto kept = others.size();
    for (auto index = std::size_t{0U}; index < others.size(); ++index)
    {
        auto const over_entries = kept > keep;
        auto const over_bytes = max_bytes != 0U && kept_bytes + incoming_size_bytes > max_bytes;
        if (!over_entries && !over_bytes)
        {
            break;
        }
        displaced.push_back(*others[index]);
        --kept;
        kept_bytes -= others[index]->size_bytes;
    }
    return displaced;
}

auto apply_remote_media_admission(LocalMediaRepository& repository, std::string_view origin_server,
                                  std::string_view media_id, std::string_view local_media_id, std::uint64_t now,
                                  std::vector<RemoteMediaCacheEntry> const& displaced) -> void
{
    // One pass over the cache removes every displaced entry (the cost is bounded by the cache cap, ADR-0633); the
    // records are erased one by one in constant time each.
    auto gone_keys = std::unordered_set<std::string>{};
    for (auto const& gone : displaced)
    {
        std::ignore = erase_record_and_release_blob(repository, gone.local_media_id);
        gone_keys.insert(gone.origin_server + '\0' + gone.media_id);
    }
    if (!gone_keys.empty())
    {
        repository.media_rows_examined.add(repository.remote_media_cache.size());
        std::erase_if(repository.remote_media_cache, [&gone_keys](RemoteMediaCacheEntry const& entry) {
            return gone_keys.contains(entry.origin_server + '\0' + entry.media_id);
        });
    }
    auto const ttl_ms = repository.config.remote_media_cache_max_entries == 0U
                            ? std::uint64_t{0U}
                            : static_cast<std::uint64_t>(repository.config.remote_media_cache_ttl_seconds) * 1000U;
    auto const* record = find_local_media_record(repository, local_media_id);
    repository.remote_media_cache.push_back({std::string{origin_server}, std::string{media_id},
                                             std::string{local_media_id}, now + ttl_ms, now,
                                             record == nullptr ? std::uint64_t{0U} : record->size_bytes});
}

auto restore_remote_media_cache(LocalMediaRepository& repository, std::vector<RemoteMediaCacheEntry> entries) -> void
{
    std::ranges::stable_sort(entries, {}, &RemoteMediaCacheEntry::last_access_ms);
    repository.remote_media_cache.clear();
    for (auto& entry : entries)
    {
        if (auto const* record = find_local_media_record(repository, entry.local_media_id); record != nullptr)
        {
            entry.size_bytes = record->size_bytes;
            repository.remote_media_cache.push_back(std::move(entry));
        }
    }
}

auto fetch_remote_media_disabled(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request)
    -> RemoteMediaDownloadResult
{
    if (!repository.config.remote_fetch_enabled)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media fetch disabled"};
    }

    auto const decision = remote_media_fetch_policy(
        {request.origin_server, request.media_id, request.resolved_host, request.resolved_addresses, true,
         repository.config.private_address_fetches_blocked, repository.config.allowed_private_fetch_ranges});
    ++repository.metrics.remote_fetch_rejections;
    if (decision.disposition == MediaDisposition::reject)
    {
        return {false, 502U, decision.reason};
    }
    return {false, 501U, "remote media fetching is disabled on this server"};
}

auto fetch_remote_media(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request, std::uint64_t now)
    -> RemoteMediaDownloadResult
{
    if (!repository.config.remote_fetch_enabled)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media fetch disabled"};
    }
    auto const remote_decision = remote_media_fetch_policy(
        {request.origin_server, request.media_id, request.resolved_host, request.resolved_addresses, true,
         repository.config.private_address_fetches_blocked, repository.config.allowed_private_fetch_ranges});
    if (remote_decision.disposition == MediaDisposition::reject)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, remote_decision.reason};
    }
    if (request.bytes.empty())
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media response body is empty"};
    }

    // OUT-4: the media service looks the cache up before the network
    // (find_cached_remote_media). Checking again here only stops two requests
    // that both missed the cache from admitting the same remote media twice.
    if (auto const* cached = find_cached_remote_media(repository, request.origin_server, request.media_id, now);
        cached != nullptr && cached->state == LocalMediaState::available)
    {
        return cached_remote_media_result(repository, *cached, request.bytes);
    }

    auto upload = LocalMediaUploadRequest{};
    upload.owner_user_id = "@remote-media:" + request.origin_server;
    upload.declared_mime_type = request.content_type;
    // Unlike the local-upload path (sniffed in homeserver/ClientServerRuntime.cpp before
    // this request is built), a remote federation response has no such upstream
    // sniffing step, so the remote server's declared Content-Type is not trustworthy
    // evidence of its own accord — sniff the fetched bytes directly.
    upload.sniffed_mime_type = sniff_mime_type(request.bytes);
    upload.bytes = request.bytes;
    upload.scanner_clean = request.scanner_clean;
    upload.decoded_size_bytes = request.decoded_size_bytes;
    upload.pixel_count = request.pixel_count;
    upload.animation_frame_count = request.animation_frame_count;
    upload.decoder_marked_safe = request.decoder_marked_safe;
    upload.from_remote_fetch = true;
    upload.upload_name = request.upload_name;
    auto const result = upload_local_media(repository, request.origin_server, upload);
    if (!result.ok)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, result.status, result.reason};
    }
    if (result.quarantined)
    {
        ++repository.metrics.remote_fetch_rejections;
        // The held record remains available for moderation, but admission to
        // storage is not permission to disclose its bytes to the requester.
        return {false,
                451U,
                "media is quarantined",
                result.content_type,
                {},
                result.size_bytes,
                result.hash_algorithm,
                result.digest,
                make_storage_id(result.digest, result.size_bytes),
                result.media_id,
                true,
                true,
                !result.deduplicated};
    }
    ++repository.metrics.remote_fetches_accepted;
    return {true,
            result.status,
            {},
            result.content_type,
            request.bytes,
            result.size_bytes,
            result.hash_algorithm,
            result.digest,
            make_storage_id(result.digest, result.size_bytes),
            result.media_id,
            result.quarantined,
            true,
            !result.deduplicated};
}

} // namespace merovingian::media
