// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/repository.hpp>

#include <merovingian/media/security.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::media
{
namespace
{

auto constexpr fnv_offset = std::uint64_t{1469598103934665603ULL};
auto constexpr fnv_prime = std::uint64_t{1099511628211ULL};

[[nodiscard]] auto media_id_is_safe(std::string_view media_id) noexcept -> bool
{
    return !media_id.empty() && media_id.find('/') == std::string_view::npos
        && media_id.find("..") == std::string_view::npos && media_id.find(' ') == std::string_view::npos;
}

[[nodiscard]] auto stable_hash(std::string_view value) noexcept -> std::uint64_t
{
    auto hash = fnv_offset;
    for (auto const character : value)
    {
        hash ^= static_cast<unsigned char>(character);
        hash *= fnv_prime;
    }
    return hash;
}

[[nodiscard]] auto hex_digit(std::uint64_t value) noexcept -> char
{
    return static_cast<char>(value < 10U ? ('0' + value) : ('a' + (value - 10U)));
}

[[nodiscard]] auto fixed_hex(std::uint64_t value) -> std::string
{
    auto output = std::string{};
    output.reserve(16U);
    for (auto shift = 60; shift >= 0; shift -= 4)
    {
        output.push_back(hex_digit((value >> static_cast<unsigned>(shift)) & 0x0FU));
    }
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

[[nodiscard]] auto find_blob(
    LocalMediaRepository& repository,
    std::string_view hash_algorithm,
    std::string_view digest,
    std::uint64_t size_bytes
) noexcept -> LocalMediaBlob*
{
    auto const iterator = std::ranges::find_if(repository.blobs, [hash_algorithm, digest, size_bytes](LocalMediaBlob const& blob) {
        return blob.hash_algorithm == hash_algorithm && blob.digest == digest && blob.size_bytes == size_bytes;
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

auto calculate_media_digest(std::string_view bytes) -> std::string
{
    return fixed_hex(stable_hash(bytes));
}

auto media_repository_summary(LocalMediaRepository const& repository) -> std::string
{
    return "Media repository: records=" + std::to_string(repository.records.size())
        + " blobs=" + std::to_string(repository.metrics.stored_blobs)
        + " stored_bytes=" + std::to_string(repository.metrics.stored_bytes)
        + " remote_fetch_enabled=" + std::string{repository.config.remote_fetch_enabled ? "true" : "false"};
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

auto upload_local_media(
    LocalMediaRepository& repository,
    std::string_view server_name,
    LocalMediaUploadRequest const& request
) -> LocalMediaUploadResult
{
    auto const digest = calculate_media_digest(request.bytes);
    auto const size_bytes = static_cast<std::uint64_t>(request.bytes.size());
    auto const content_type = canonical_content_type(request);
    auto const scanner_clean = repository.config.enable_av_scanner ? request.scanner_clean : true;
    auto const decision = evaluate_media_upload(
        upload_policy(repository.config),
        {size_bytes, request.declared_mime_type, request.sniffed_mime_type, digest, scanner_clean}
    );

    if (decision.disposition == MediaDisposition::reject)
    {
        ++repository.metrics.uploads_rejected;
        return {false, 413U, {}, {}, {}, size_bytes, "fnv1a64", digest, false, false, decision.reason};
    }

    auto deduplicated = false;
    auto* blob = find_blob(repository, "fnv1a64", digest, size_bytes);
    if (blob == nullptr)
    {
        auto new_blob = LocalMediaBlob{};
        new_blob.storage_id = make_storage_id(digest, size_bytes);
        new_blob.hash_algorithm = "fnv1a64";
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
    record.hash_algorithm = "fnv1a64";
    record.digest = digest;
    record.storage_id = blob->storage_id;
    record.state = decision.disposition == MediaDisposition::quarantine ? LocalMediaState::quarantined
                                                                        : LocalMediaState::available;
    record.quarantine_reason = decision.reason;
    auto const media_id = record.media_id;
    repository.records.push_back(std::move(record));

    ++repository.metrics.uploads_accepted;
    if (decision.disposition == MediaDisposition::quarantine)
    {
        ++repository.metrics.uploads_quarantined;
    }
    refresh_storage_metrics(repository);

    return {
        true,
        decision.disposition == MediaDisposition::quarantine ? 202U : 200U,
        media_id,
        "mxc://" + std::string{server_name} + "/" + media_id,
        content_type,
        size_bytes,
        "fnv1a64",
        digest,
        deduplicated,
        decision.disposition == MediaDisposition::quarantine,
        decision.reason,
    };
}

auto download_local_media(
    LocalMediaRepository& repository,
    std::string_view server_name,
    std::string_view media_id
) -> LocalMediaDownloadResult
{
    (void)server_name;
    if (!media_id_is_safe(media_id))
    {
        ++repository.metrics.downloads_blocked;
        return {false, 400U, {}, {}, "invalid media id"};
    }

    auto const* record = find_local_media_record(repository, media_id);
    if (record == nullptr || record->state == LocalMediaState::removed)
    {
        ++repository.metrics.downloads_blocked;
        return {false, 404U, {}, {}, "media not found"};
    }
    if (record->state == LocalMediaState::quarantined)
    {
        ++repository.metrics.downloads_blocked;
        return {false, 451U, {}, {}, "media is quarantined"};
    }

    auto const* blob = find_blob(repository, record->storage_id);
    if (blob == nullptr)
    {
        ++repository.metrics.downloads_blocked;
        return {false, 500U, {}, {}, "media blob missing"};
    }

    ++repository.metrics.downloads_served;
    return {true, 200U, record->content_type, blob->bytes, {}};
}

auto quarantine_local_media(
    LocalMediaRepository& repository,
    std::string_view media_id,
    std::string_view reason
) -> LocalMediaAdminResult
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
    return {true, 200U, record->media_id, record->state, "released"};
}

auto remove_local_media(
    LocalMediaRepository& repository,
    std::string_view media_id,
    std::string_view reason
) -> LocalMediaAdminResult
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
    return {true, 200U, record->media_id, record->state, "removed"};
}

auto fetch_remote_media_disabled(
    LocalMediaRepository& repository,
    RemoteMediaDownloadRequest const& request
) -> RemoteMediaDownloadResult
{
    if (!repository.config.remote_fetch_enabled)
    {
        ++repository.metrics.remote_fetch_rejections;
        return {false, 502U, "remote media fetch disabled"};
    }

    auto const decision = remote_media_fetch_policy(
        {request.origin_server, request.media_id, request.resolved_host, request.resolved_addresses, true, repository.config.private_address_fetches_blocked}
    );
    ++repository.metrics.remote_fetch_rejections;
    if (decision.disposition == MediaDisposition::reject)
    {
        return {false, 502U, decision.reason};
    }
    return {false, 501U, "remote media fetch is not implemented in this milestone"};
}

} // namespace merovingian::media
