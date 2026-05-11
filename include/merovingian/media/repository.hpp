// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/media/runtime_media.hpp>
#include <merovingian/observability/observability.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::media
{

enum class LocalMediaState
{
    available,
    quarantined,
    removed,
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
    std::uint64_t stored_blobs{0U};
    std::uint64_t stored_bytes{0U};
};

struct LocalMediaRepository final
{
    RuntimeMediaConfig config{};
    std::vector<LocalMediaRecord> records{};
    std::vector<LocalMediaBlob> blobs{};
    MediaRepositoryMetrics metrics{};
    std::uint64_t next_media_sequence{1U};
};

struct LocalMediaUploadRequest final
{
    std::string owner_user_id{};
    std::string declared_mime_type{};
    std::string sniffed_mime_type{};
    std::string bytes{};
    bool scanner_clean{true};
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
};

struct RemoteMediaDownloadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
};

[[nodiscard]] auto local_media_state_name(LocalMediaState state) noexcept -> char const*;
[[nodiscard]] auto make_local_media_repository(RuntimeMediaConfig config) -> LocalMediaRepository;
[[nodiscard]] auto calculate_media_digest(std::string_view bytes) -> std::string;
[[nodiscard]] auto media_repository_summary(LocalMediaRepository const& repository) -> std::string;
[[nodiscard]] auto media_repository_metrics(LocalMediaRepository const& repository) -> std::vector<observability::MetricSample>;
[[nodiscard]] auto find_local_media_record(
    LocalMediaRepository const& repository,
    std::string_view media_id
) noexcept -> LocalMediaRecord const*;
[[nodiscard]] auto upload_local_media(
    LocalMediaRepository& repository,
    std::string_view server_name,
    LocalMediaUploadRequest const& request
) -> LocalMediaUploadResult;
[[nodiscard]] auto download_local_media(
    LocalMediaRepository& repository,
    std::string_view server_name,
    std::string_view media_id
) -> LocalMediaDownloadResult;
[[nodiscard]] auto quarantine_local_media(
    LocalMediaRepository& repository,
    std::string_view media_id,
    std::string_view reason
) -> LocalMediaAdminResult;
[[nodiscard]] auto release_local_media(
    LocalMediaRepository& repository,
    std::string_view media_id
) -> LocalMediaAdminResult;
[[nodiscard]] auto remove_local_media(
    LocalMediaRepository& repository,
    std::string_view media_id,
    std::string_view reason
) -> LocalMediaAdminResult;
[[nodiscard]] auto fetch_remote_media_disabled(
    LocalMediaRepository& repository,
    RemoteMediaDownloadRequest const& request
) -> RemoteMediaDownloadResult;

} // namespace merovingian::media
