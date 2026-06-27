// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/repository.hpp"

#include "merovingian/media/security.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <sodium.h>

namespace merovingian::media
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("media_repository", event, fields, severity);
    }

    auto constexpr media_digest_bytes = std::size_t{crypto_generichash_BYTES};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }
    [[nodiscard]] auto media_id_is_safe(std::string_view media_id) noexcept -> bool
    {
        return !media_id.empty() && media_id.find('/') == std::string_view::npos &&
               media_id.find("..") == std::string_view::npos && media_id.find(' ') == std::string_view::npos;
    }

    [[nodiscard]] auto to_hex(unsigned char const* bytes, std::size_t size) -> std::string
    {
        auto output = std::string((size * 2U) + 1U, '\0');
        std::ignore = sodium_bin2hex(output.data(), output.size(), bytes, size);
        output.pop_back();
        return output;
    }

    [[nodiscard]] auto upload_policy(RuntimeMediaConfig const& config) -> MediaUploadPolicy
    {
        return {config.max_upload_bytes, config.allowed_mime_types, true, config.quarantine_unknown_mime, true};
    }

    [[nodiscard]] auto canonical_content_type(LocalMediaUploadRequest const& request) -> std::string
    {
        return request.sniffed_mime_type.empty() ? request.declared_mime_type : request.sniffed_mime_type;
    }

    [[nodiscard]] auto find_live_blob(LocalMediaRepository& repository, std::string_view hash_algorithm,
                                      std::string_view digest, std::uint64_t size_bytes) noexcept -> LocalMediaBlob*
    {
        auto const iterator =
            std::ranges::find_if(repository.blobs, [hash_algorithm, digest, size_bytes](LocalMediaBlob const& blob) {
                return blob.ref_count > 0U && blob.hash_algorithm == hash_algorithm && blob.digest == digest &&
                       blob.size_bytes == size_bytes;
            });
        return iterator == repository.blobs.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_blob(LocalMediaRepository const& repository, std::string_view storage_id) noexcept
        -> LocalMediaBlob const*
    {
        auto const iterator = std::ranges::find_if(repository.blobs, [storage_id](LocalMediaBlob const& blob) {
            return blob.storage_id == storage_id && blob.ref_count > 0U;
        });
        return iterator == repository.blobs.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_record(LocalMediaRepository& repository, std::string_view media_id) noexcept
        -> LocalMediaRecord*
    {
        auto const iterator = std::ranges::find_if(repository.records, [media_id](LocalMediaRecord const& record) {
            return record.media_id == media_id;
        });
        return iterator == repository.records.end() ? nullptr : &(*iterator);
    }

    auto refresh_storage_metrics(LocalMediaRepository& repository) -> void
    {
        auto stored_blobs = std::uint64_t{0U};
        auto stored_bytes = std::uint64_t{0U};
        for (auto const& blob : repository.blobs)
        {
            if (blob.ref_count == 0U)
            {
                continue;
            }
            ++stored_blobs;
            stored_bytes += blob.size_bytes;
        }
        repository.metrics.stored_blobs = stored_blobs;
        repository.metrics.stored_bytes = stored_bytes;
    }

    [[nodiscard]] auto make_media_id(LocalMediaRepository& repository, std::string_view digest) -> std::string
    {
        auto const sequence = repository.next_media_sequence++;
        auto const prefix = digest.substr(0U, std::min<std::size_t>(12U, digest.size()));
        return "m" + std::to_string(sequence) + "_" + std::string{prefix};
    }

    [[nodiscard]] auto make_storage_id(std::string_view digest, std::uint64_t size_bytes) -> std::string
    {
        return "blob_" + std::string{digest} + "_" + std::to_string(size_bytes);
    }

    [[nodiscard]] auto decoder_policy(RuntimeMediaConfig const& config) -> DecoderSafetyPolicy
    {
        auto const max_input =
            config.max_decode_input_bytes == 0U ? config.max_upload_bytes : config.max_decode_input_bytes;
        auto const max_output = config.max_decode_output_bytes == 0U
                                    ? config.max_upload_bytes * config.max_decompression_ratio
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
            // Saturating multiply: prevent uint64_t wrap when max_upload_bytes is extreme.
            constexpr auto max_safe = std::numeric_limits<std::uint64_t>::max() / 64U;
            auto const scaled = config.max_upload_bytes > max_safe ? std::numeric_limits<std::uint64_t>::max()
                                                                   : config.max_upload_bytes * 64U;
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
        return content_type == "image/png" || content_type == "image/jpeg" || content_type == "image/gif";
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
        // by the sandboxed out-of-process worker (see media/thumbnailer.hpp and
        // download_local_media_thumbnail), which decodes the original blob and
        // resamples to the requested geometry. This entry simply records that the
        // source is a resamplable image type.
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
    if (!sodium_is_ready())
    {
        return {};
    }
    auto digest = std::array<unsigned char, media_digest_bytes>{};
    auto media_bytes = std::vector<unsigned char>{};
    media_bytes.reserve(bytes.size());
    for (auto const byte : bytes)
    {
        media_bytes.push_back(static_cast<unsigned char>(byte));
    }
    if (crypto_generichash(digest.data(), digest.size(), media_bytes.data(), media_bytes.size(), nullptr, 0U) != 0)
    {
        return {};
    }
    return to_hex(digest.data(), digest.size());
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

auto find_local_media_record(LocalMediaRepository const& repository, std::string_view media_id) noexcept
    -> LocalMediaRecord const*
{
    auto const iterator = std::ranges::find_if(repository.records, [media_id](LocalMediaRecord const& record) {
        return record.media_id == media_id;
    });
    return iterator == repository.records.end() ? nullptr : &(*iterator);
}

auto find_local_media_blob(LocalMediaRepository const& repository, std::string_view storage_id) noexcept
    -> LocalMediaBlob const*
{
    auto const iterator = std::ranges::find_if(repository.blobs, [storage_id](LocalMediaBlob const& blob) {
        return blob.storage_id == storage_id;
    });
    return iterator == repository.blobs.end() ? nullptr : &(*iterator);
}

auto find_local_media_thumbnail(LocalMediaRepository const& repository, std::string_view media_id) noexcept
    -> LocalMediaThumbnail const*
{
    auto const iterator = std::ranges::find_if(repository.thumbnails, [media_id](LocalMediaThumbnail const& thumb) {
        return thumb.media_id == media_id;
    });
    return iterator == repository.thumbnails.end() ? nullptr : &(*iterator);
}

auto restore_local_media_repository(LocalMediaRepository& repository, std::vector<LocalMediaRecord> records,
                                    std::vector<LocalMediaBlob> blobs) -> void
{
    repository.records = std::move(records);
    repository.blobs = std::move(blobs);
    repository.thumbnails.clear();
    repository.next_media_sequence = static_cast<std::uint64_t>(repository.records.size()) + 1U;
    for (auto const& record : repository.records)
    {
        record_thumbnail(repository, record);
    }
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
    auto const decision =
        evaluate_media_upload(upload_policy(repository.config), {size_bytes, request.declared_mime_type,
                                                                 request.sniffed_mime_type, digest, scanner_clean});

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

    auto deduplicated = false;
    auto* blob = find_live_blob(repository, "blake2b", digest, size_bytes);
    if (blob == nullptr)
    {
        auto new_blob = LocalMediaBlob{};
        new_blob.storage_id = make_storage_id(digest, size_bytes);
        new_blob.hash_algorithm = "blake2b";
        new_blob.digest = digest;
        new_blob.size_bytes = size_bytes;
        new_blob.bytes = request.bytes;
        new_blob.ref_count = 1U;
        repository.blobs.push_back(std::move(new_blob));
        blob = &repository.blobs.back();
    }
    else
    {
        ++blob->ref_count;
        deduplicated = true;
        ++repository.metrics.deduplicated_uploads;
    }

    auto record = LocalMediaRecord{};
    record.media_id = make_media_id(repository, digest);
    record.owner_user_id = request.owner_user_id;
    record.content_type = content_type;
    record.size_bytes = size_bytes;
    record.hash_algorithm = "blake2b";
    record.digest = digest;
    record.storage_id = blob->storage_id;
    record.state = decision.disposition == MediaDisposition::quarantine ? LocalMediaState::quarantined
                                                                        : LocalMediaState::available;
    record.quarantine_reason = decision.reason;
    auto const media_id = record.media_id;
    repository.records.push_back(std::move(record));
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

auto download_local_media(LocalMediaRepository& repository, std::string_view server_name, std::string_view media_id)
    -> LocalMediaDownloadResult
{
    std::ignore = server_name;
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
    if (record == nullptr || record->state == LocalMediaState::removed)
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

    auto const* blob = find_blob(repository, record->storage_id);
    if (blob == nullptr)
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
    return {true, 200U, record->content_type, blob->bytes, {}};
}

auto quarantine_local_media(LocalMediaRepository& repository, std::string_view media_id, std::string_view reason)
    -> LocalMediaAdminResult
{
    if (!media_id_is_safe(media_id))
    {
        return {false, 400U, {}, LocalMediaState::available, "invalid media id"};
    }
    if (reason.empty())
    {
        return {false, 400U, std::string{media_id}, LocalMediaState::available, "quarantine reason is required"};
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr || record->state == LocalMediaState::removed)
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
    if (!media_id_is_safe(media_id))
    {
        return {false, 400U, {}, LocalMediaState::available, "invalid media id"};
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr || record->state == LocalMediaState::removed)
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
    if (!media_id_is_safe(media_id))
    {
        return {false, 400U, {}, LocalMediaState::available, "invalid media id"};
    }
    if (reason.empty())
    {
        return {false, 400U, std::string{media_id}, LocalMediaState::available, "removal reason is required"};
    }
    auto* record = find_record(repository, media_id);
    if (record == nullptr || record->state == LocalMediaState::removed)
    {
        return {false, 404U, std::string{media_id}, LocalMediaState::removed, "media not found"};
    }

    auto const storage_id = record->storage_id;
    record->state = LocalMediaState::removed;
    record->quarantine_reason = std::string{reason};
    auto const iterator = std::ranges::find_if(repository.blobs, [&storage_id](LocalMediaBlob const& blob) {
        return blob.storage_id == storage_id;
    });
    if (iterator != repository.blobs.end() && iterator->ref_count > 0U)
    {
        --iterator->ref_count;
        if (iterator->ref_count == 0U)
        {
            iterator->bytes.clear();
        }
    }

    ++repository.metrics.admin_removals;
    refresh_storage_metrics(repository);
    log_diagnostic("admin.removed", {
                                        {"media_id", record->media_id,    false},
                                        {"reason",   std::string{reason}, false}
    });
    return {true, 200U, record->media_id, record->state, "removed"};
}

auto fetch_remote_media_disabled(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request)
    -> RemoteMediaDownloadResult
{
    if (!repository.config.remote_fetch_enabled)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media fetch disabled"};
    }

    auto const decision = remote_media_fetch_policy({request.origin_server, request.media_id, request.resolved_host,
                                                     request.resolved_addresses, true,
                                                     repository.config.private_address_fetches_blocked});
    ++repository.metrics.remote_fetch_rejections;
    if (decision.disposition == MediaDisposition::reject)
    {
        return {false, 502U, decision.reason};
    }
    return {false, 501U, "remote media fetch is not implemented in this milestone"};
}

auto fetch_remote_media(LocalMediaRepository& repository, RemoteMediaDownloadRequest const& request)
    -> RemoteMediaDownloadResult
{
    if (!repository.config.remote_fetch_enabled)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media fetch disabled"};
    }
    auto const remote_decision = remote_media_fetch_policy({request.origin_server, request.media_id,
                                                            request.resolved_host, request.resolved_addresses, true,
                                                            repository.config.private_address_fetches_blocked});
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

    auto upload = LocalMediaUploadRequest{};
    upload.owner_user_id = "@remote-media:" + request.origin_server;
    upload.declared_mime_type = request.content_type;
    upload.sniffed_mime_type = request.content_type;
    upload.bytes = request.bytes;
    upload.scanner_clean = request.scanner_clean;
    upload.decoded_size_bytes = request.decoded_size_bytes;
    upload.pixel_count = request.pixel_count;
    upload.animation_frame_count = request.animation_frame_count;
    upload.decoder_marked_safe = request.decoder_marked_safe;
    auto const result = upload_local_media(repository, request.origin_server, upload);
    if (!result.ok)
    {
        return {false, result.status, result.reason};
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
            result.quarantined};
}

} // namespace merovingian::media
