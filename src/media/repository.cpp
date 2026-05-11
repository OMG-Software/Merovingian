// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/repository.hpp>

#include <merovingian/media/security.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::media
{
namespace
{

constexpr auto sha256_initial = std::array<std::uint32_t, 8U>{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};
constexpr auto sha256_round_constants = std::array<std::uint32_t, 64U>{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

[[nodiscard]] auto rotate_right(std::uint32_t value, unsigned shift) noexcept -> std::uint32_t
{
    return (value >> shift) | (value << (32U - shift));
}

[[nodiscard]] auto hex_digit(std::uint32_t value) noexcept -> char
{
    return static_cast<char>(value < 10U ? ('0' + value) : ('a' + (value - 10U)));
}

[[nodiscard]] auto word_hex(std::uint32_t value) -> std::string
{
    auto output = std::string{};
    output.reserve(8U);
    for (auto shift = 28; shift >= 0; shift -= 4)
    {
        output.push_back(hex_digit((value >> static_cast<unsigned>(shift)) & 0x0FU));
    }
    return output;
}

[[nodiscard]] auto media_id_is_safe(std::string_view media_id) noexcept -> bool
{
    return !media_id.empty() && media_id.find('/') == std::string_view::npos
        && media_id.find("..") == std::string_view::npos && media_id.find(' ') == std::string_view::npos;
}

[[nodiscard]] auto sha256_hex(std::string_view bytes) -> std::string
{
    auto message = std::string{bytes};
    auto const bit_length = static_cast<std::uint64_t>(message.size()) * 8U;
    message.push_back(static_cast<char>(0x80));
    while ((message.size() % 64U) != 56U)
    {
        message.push_back('\0');
    }
    for (auto shift = 56; shift >= 0; shift -= 8)
    {
        message.push_back(static_cast<char>((bit_length >> static_cast<unsigned>(shift)) & 0xffU));
    }

    auto hash = sha256_initial;
    for (auto offset = std::size_t{0U}; offset < message.size(); offset += 64U)
    {
        auto words = std::array<std::uint32_t, 64U>{};
        for (auto index = std::size_t{0U}; index < 16U; ++index)
        {
            auto const base = offset + (index * 4U);
            words[index] = (static_cast<std::uint32_t>(static_cast<unsigned char>(message[base])) << 24U)
                | (static_cast<std::uint32_t>(static_cast<unsigned char>(message[base + 1U])) << 16U)
                | (static_cast<std::uint32_t>(static_cast<unsigned char>(message[base + 2U])) << 8U)
                | static_cast<std::uint32_t>(static_cast<unsigned char>(message[base + 3U]));
        }
        for (auto index = std::size_t{16U}; index < 64U; ++index)
        {
            auto const s0 = rotate_right(words[index - 15U], 7U) ^ rotate_right(words[index - 15U], 18U) ^ (words[index - 15U] >> 3U);
            auto const s1 = rotate_right(words[index - 2U], 17U) ^ rotate_right(words[index - 2U], 19U) ^ (words[index - 2U] >> 10U);
            words[index] = words[index - 16U] + s0 + words[index - 7U] + s1;
        }

        auto a = hash[0U];
        auto b = hash[1U];
        auto c = hash[2U];
        auto d = hash[3U];
        auto e = hash[4U];
        auto f = hash[5U];
        auto g = hash[6U];
        auto h = hash[7U];

        for (auto index = std::size_t{0U}; index < 64U; ++index)
        {
            auto const s1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
            auto const choice = (e & f) ^ ((~e) & g);
            auto const temp1 = h + s1 + choice + sha256_round_constants[index] + words[index];
            auto const s0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
            auto const majority = (a & b) ^ (a & c) ^ (b & c);
            auto const temp2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0U] += a;
        hash[1U] += b;
        hash[2U] += c;
        hash[3U] += d;
        hash[4U] += e;
        hash[5U] += f;
        hash[6U] += g;
        hash[7U] += h;
    }

    auto output = std::string{};
    output.reserve(64U);
    for (auto const word : hash)
    {
        output += word_hex(word);
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

[[nodiscard]] auto find_live_blob(
    LocalMediaRepository& repository,
    std::string_view hash_algorithm,
    std::string_view digest,
    std::uint64_t size_bytes
) noexcept -> LocalMediaBlob*
{
    auto const iterator = std::ranges::find_if(repository.blobs, [hash_algorithm, digest, size_bytes](LocalMediaBlob const& blob) {
        return blob.ref_count > 0U && blob.hash_algorithm == hash_algorithm && blob.digest == digest && blob.size_bytes == size_bytes;
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
    return sha256_hex(bytes);
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
        return {false, 413U, {}, {}, {}, size_bytes, "sha256", digest, false, false, decision.reason};
    }

    auto deduplicated = false;
    auto* blob = find_live_blob(repository, "sha256", digest, size_bytes);
    if (blob == nullptr)
    {
        auto new_blob = LocalMediaBlob{};
        new_blob.storage_id = make_storage_id(digest, size_bytes);
        new_blob.hash_algorithm = "sha256";
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
    record.hash_algorithm = "sha256";
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
        "sha256",
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
