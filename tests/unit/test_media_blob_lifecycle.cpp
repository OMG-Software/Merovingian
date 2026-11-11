// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/LocalMediaRecord.hpp"
#include "merovingian/media/LocalMediaRepository.hpp"
#include "merovingian/media/LocalMediaState.hpp"
#include "merovingian/media/LocalMediaUploadRequest.hpp"
#include "merovingian/media/LocalMediaUploadResult.hpp"
#include "merovingian/media/MediaAcceptancePolicy.hpp"
#include "merovingian/media/RemoteMediaDownloadRequest.hpp"
#include "merovingian/media/RemoteMediaDownloadResult.hpp"
#include "merovingian/media/RuntimeMediaConfig.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace media = merovingian::media;

[[nodiscard]] auto lifecycle_repository(std::uint64_t cache_entries) -> media::LocalMediaRepository
{
    auto config = media::RuntimeMediaConfig{};
    config.max_upload_bytes = 16U;
    config.allowed_mime_types = {"text/plain", "image/png"};
    config.quarantine_unknown_mime = true;
    config.enable_av_scanner = true;
    config.private_address_fetches_blocked = true;
    config.remote_fetch_timeout_seconds = 30U;
    config.remote_fetch_enabled = true;
    config.remote_fetch_media_policy = media::MediaAcceptancePolicy::allow_after_scan;
    config.decode_in_sandbox = true;
    config.thumbnailing_enabled = true;
    config.remote_media_cache_max_entries = cache_entries;
    config.remote_media_cache_ttl_seconds = 3600U;
    return media::make_local_media_repository(config);
}

// Eight bytes of PNG signature and two bytes that make the file unique, so each `serial` is its own blob.
[[nodiscard]] auto png_bytes(std::uint32_t serial) -> std::string
{
    auto bytes = std::string{"\x89PNG\r\n\x1a\n", 8U};
    bytes.push_back(static_cast<char>('a' + (serial / 26U) % 26U));
    bytes.push_back(static_cast<char>('a' + serial % 26U));
    return bytes;
}

[[nodiscard]] auto local_png(media::LocalMediaRepository& repository, std::uint32_t serial, std::string owner)
    -> media::LocalMediaUploadResult
{
    return media::upload_local_media(repository, "example.org",
                                     {std::move(owner), "image/png", "image/png", png_bytes(serial), true});
}

[[nodiscard]] auto remote_request(std::string media_id, std::string bytes)
    -> media::RemoteMediaDownloadRequest
{
    return {"remote.example.org", std::move(media_id), "remote.example.org", {"203.0.113.20"}, "image/png",
            std::move(bytes),     true,                16U,                  64U,
            1U,                   true};
}

// What the media service does around its database commit: admit, plan the displacement, apply it.
[[nodiscard]] auto admit_remote(media::LocalMediaRepository& repository, std::string media_id, std::string bytes,
                                std::uint64_t now) -> media::RemoteMediaDownloadResult
{
    auto const request = remote_request(std::move(media_id), std::move(bytes));
    auto const result = media::fetch_remote_media(repository, request, now);
    if (result.admitted_new_record)
    {
        auto const displaced = media::plan_remote_media_admission(repository, request.origin_server, request.media_id,
                                                                  result.size_bytes, now);
        media::apply_remote_media_admission(repository, request.origin_server, request.media_id,
                                            result.local_media_id, now, displaced);
    }
    return result;
}

[[nodiscard]] auto blob_references(media::LocalMediaRepository& repository, std::string const& storage_id)
    -> std::uint64_t
{
    auto const* blob = media::find_local_media_blob(repository, storage_id);
    return blob == nullptr ? std::uint64_t{0U} : blob->ref_count;
}

} // namespace

SCENARIO("A removed cached remote file that is later displaced does not release its blob a second time",
         "[media][repository][blob-release][gate-l]")
{
    GIVEN("a local upload and a cached remote file with the same bytes, so one blob has two references")
    {
        auto repository = lifecycle_repository(1U);
        auto const now = media::remote_media_cache_now_ms();
        auto const local = local_png(repository, 0U, "@alice:example.org");
        auto const cached = admit_remote(repository, "evilA", png_bytes(0U), now);
        REQUIRE(local.ok);
        REQUIRE(cached.ok);
        auto const storage_id = media::make_local_media_storage_id(local.digest, local.size_bytes);
        REQUIRE(blob_references(repository, storage_id) == 2U);

        WHEN("an administrator removes the cached copy and a later fetch displaces its cache entry")
        {
            REQUIRE(media::remove_local_media(repository, cached.local_media_id, "abuse").ok);
            auto const after_removal = blob_references(repository, storage_id);
            auto const next = admit_remote(repository, "evilB", png_bytes(1U), now + 1U);

            THEN("the shared blob keeps the one reference the local upload holds, and the local file is served")
            {
                REQUIRE(next.ok);
                CHECK(after_removal == 1U);
                CHECK(blob_references(repository, storage_id) == 1U);
                auto const download = media::resolve_local_media_download(repository, local.media_id);
                CHECK(download.ok);
                CHECK(download.storage_id == storage_id);
                CHECK(media::find_local_media_record(repository, cached.local_media_id) == nullptr);
            }
        }

        WHEN("the cached copy is displaced without having been removed")
        {
            auto const next = admit_remote(repository, "evilB", png_bytes(1U), now + 1U);

            THEN("it releases its reference exactly once")
            {
                REQUIRE(next.ok);
                CHECK(blob_references(repository, storage_id) == 1U);
                CHECK(media::resolve_local_media_download(repository, local.media_id).ok);
            }
        }
    }
}

SCENARIO("A blob is dropped when its last reference goes, and the same bytes can be stored again",
         "[media][repository][zero-ref][gate-l]")
{
    GIVEN("a repository that caches one remote file at a time")
    {
        auto repository = lifecycle_repository(1U);
        auto const now = media::remote_media_cache_now_ms();

        WHEN("three hundred distinct remote files pass through the cache")
        {
            for (auto serial = std::uint32_t{0U}; serial < 300U; ++serial)
            {
                REQUIRE(admit_remote(repository, "media" + std::to_string(serial), png_bytes(serial), now + serial).ok);
            }

            THEN("only the cached file's blob is held, in the rows and in the metrics")
            {
                CHECK(repository.records.size() == 1U);
                CHECK(repository.blobs.size() == 1U);
                CHECK(repository.thumbnails.size() == 1U);
                CHECK(repository.metrics.stored_blobs == 1U);
                CHECK(repository.metrics.stored_bytes == 10U);
            }

            AND_WHEN("an evicted file is fetched again")
            {
                auto const again = admit_remote(repository, "media0", png_bytes(0U), now + 1000U);

                THEN("it is stored anew and served")
                {
                    REQUIRE(again.ok);
                    CHECK(again.stored_new_blob);
                    CHECK(repository.blobs.size() == 1U);
                    CHECK(media::resolve_local_media_download(repository, again.local_media_id).ok);
                }
            }
        }

        WHEN("a local file is removed and the same bytes are uploaded again")
        {
            auto const first = local_png(repository, 7U, "@alice:example.org");
            REQUIRE(media::remove_local_media(repository, first.media_id, "retention").ok);
            auto const rows_after_removal = repository.blobs.size();
            auto const second = local_png(repository, 7U, "@alice:example.org");

            THEN("the removal left no row and the re-upload is a new, servable blob")
            {
                CHECK(rows_after_removal == 0U);
                REQUIRE(second.ok);
                CHECK_FALSE(second.deduplicated);
                CHECK(repository.blobs.size() == 1U);
                CHECK(repository.blobs.front().ref_count == 1U);
                CHECK(media::resolve_local_media_download(repository, second.media_id).ok);
                CHECK(repository.metrics.stored_blobs == 1U);
            }
        }
    }
}

SCENARIO("Evicting a cached remote file costs work that does not grow with the records held",
         "[media][repository][eviction-cost][gate-l]")
{
    constexpr auto work_bound = std::uint64_t{48U};
    auto const evictions_cost = [](std::uint32_t local_records) {
        auto repository = lifecycle_repository(1U);
        auto const now = media::remote_media_cache_now_ms();
        for (auto serial = std::uint32_t{0U}; serial < local_records; ++serial)
        {
            REQUIRE(local_png(repository, 1000U + serial, "@user" + std::to_string(serial % 7U) + ":example.org").ok);
        }
        REQUIRE(admit_remote(repository, "first", png_bytes(0U), now).ok);
        auto worst = std::uint64_t{0U};
        for (auto serial = std::uint32_t{1U}; serial <= 20U; ++serial)
        {
            auto const before = repository.media_rows_examined.value();
            REQUIRE(admit_remote(repository, "m" + std::to_string(serial), png_bytes(serial), now + serial).ok);
            worst = std::max(worst, repository.media_rows_examined.value() - before);
        }
        return std::pair{worst, std::move(repository)};
    };

    GIVEN("repositories holding 40 and 1500 local records, each with a one-entry remote cache")
    {
        WHEN("twenty remote files are admitted, each displacing the last")
        {
            auto small = evictions_cost(40U);
            auto large = evictions_cost(1500U);

            THEN("each admission visits a bounded number of rows however many records are held")
            {
                CHECK(small.first <= work_bound);
                CHECK(large.first <= work_bound);
            }

            THEN("every local file is still found, served and counted after the evictions moved records around")
            {
                auto& repository = large.second;
                CHECK(repository.records.size() == 1501U);
                CHECK(repository.metrics.stored_blobs == 1501U);
                CHECK(repository.thumbnails.size() == 1501U);
                for (auto serial = std::uint32_t{0U}; serial < 1500U; ++serial)
                {
                    auto found = false;
                    for (auto const& record : repository.records)
                    {
                        if (record.digest == media::calculate_media_digest(png_bytes(1000U + serial)))
                        {
                            found = media::resolve_local_media_download(repository, record.media_id).ok &&
                                    media::find_local_media_thumbnail(repository, record.media_id) != nullptr;
                            break;
                        }
                    }
                    REQUIRE(found);
                }
            }
        }
    }
}

SCENARIO("Capacity limits follow removals and deduplicated uploads without a scan",
         "[media][repository][capacity][gate-l]")
{
    GIVEN("a repository limited to two files in total and one file per user pair of records")
    {
        auto repository = lifecycle_repository(8U);
        repository.config.max_total_bytes = 20U;
        repository.config.max_bytes_per_user = 20U;
        repository.config.max_records = 3U;
        auto const first = local_png(repository, 1U, "@alice:example.org");
        auto const second = local_png(repository, 2U, "@alice:example.org");
        REQUIRE(first.ok);
        REQUIRE(second.ok);

        WHEN("a third distinct file would cross the byte limit")
        {
            auto const third = local_png(repository, 3U, "@alice:example.org");

            THEN("it is refused")
            {
                CHECK_FALSE(third.ok);
                CHECK(third.status == 507U);
            }
        }

        WHEN("a copy of an existing file is uploaded, then one original is removed and a new file uploaded")
        {
            auto const copy = local_png(repository, 1U, "@bob:example.org");
            auto const over_records = local_png(repository, 4U, "@bob:example.org");
            REQUIRE(media::remove_local_media(repository, first.media_id, "retention").ok);
            auto const still_shared = local_png(repository, 5U, "@bob:example.org");
            REQUIRE(media::remove_local_media(repository, copy.media_id, "retention").ok);
            auto const freed = local_png(repository, 6U, "@bob:example.org");

            THEN("the copy adds no bytes, the record cap holds removed records, and bytes free once no record holds them")
            {
                CHECK(copy.ok);
                CHECK(copy.deduplicated);
                CHECK_FALSE(over_records.ok);
                CHECK(over_records.reason == "media repository record limit reached");
                CHECK_FALSE(still_shared.ok);
                CHECK(still_shared.reason == "media repository record limit reached");
                CHECK_FALSE(freed.ok);
                CHECK(freed.reason == "media repository record limit reached");
            }
        }
    }
}
