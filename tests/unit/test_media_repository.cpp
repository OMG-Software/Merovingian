// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/repository.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace
{

[[nodiscard]] auto test_repository() -> merovingian::media::LocalMediaRepository
{
    auto config = merovingian::media::RuntimeMediaConfig{};
    config.max_upload_bytes = 16U;
    config.allowed_mime_types = {"text/plain", "image/png"};
    config.quarantine_unknown_mime = true;
    config.enable_av_scanner = true;
    config.private_address_fetches_blocked = true;
    config.remote_fetch_timeout_seconds = 30U;
    config.remote_fetch_enabled = false;
    config.decode_in_sandbox = true;
    return merovingian::media::make_local_media_repository(config);
}

} // namespace

SCENARIO("Local media repository uploads, downloads, and deduplicates safe media",
         "[media][repository]")
{
    GIVEN("a configured local media repository")
    {
        auto repository = test_repository();

        WHEN("the same safe content is uploaded twice")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "hello", true});
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "hello", true});
            auto const downloaded =
                merovingian::media::download_local_media(repository, "example.org", first.media_id);

            THEN("two media records reference one stored blob and bytes are served safely")
            {
                REQUIRE(first.ok);
                REQUIRE(first.hash_algorithm == "sha256");
                REQUIRE(first.digest.size() == 64U);
                REQUIRE_FALSE(first.deduplicated);
                REQUIRE_FALSE(first.quarantined);
                REQUIRE(second.ok);
                REQUIRE(second.deduplicated);
                REQUIRE(repository.records.size() == 2U);
                REQUIRE(repository.blobs.size() == 1U);
                REQUIRE(repository.blobs.front().ref_count == 2U);
                REQUIRE(repository.metrics.deduplicated_uploads == 1U);
                REQUIRE(downloaded.ok);
                REQUIRE(downloaded.content_type == "text/plain");
                REQUIRE(downloaded.bytes == "hello");
            }
        }
    }
}

SCENARIO("Local media repository quarantines scanner failures and blocks downloads until release",
         "[media][repository][quarantine]")
{
    GIVEN("a configured local media repository")
    {
        auto repository = test_repository();

        WHEN("scanner failure quarantines an upload")
        {
            auto const uploaded = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "image/png", "image/png", "png-bytes", false});
            auto const blocked = merovingian::media::download_local_media(repository, "example.org",
                                                                          uploaded.media_id);
            auto const released =
                merovingian::media::release_local_media(repository, uploaded.media_id);
            auto const downloaded = merovingian::media::download_local_media(
                repository, "example.org", uploaded.media_id);

            THEN("quarantined media cannot be served until an admin release")
            {
                REQUIRE(uploaded.ok);
                REQUIRE(uploaded.quarantined);
                REQUIRE(repository.metrics.uploads_quarantined == 1U);
                REQUIRE_FALSE(blocked.ok);
                REQUIRE(blocked.status == 451U);
                REQUIRE(released.ok);
                REQUIRE(downloaded.ok);
                REQUIRE(downloaded.bytes == "png-bytes");
            }
        }
    }
}

SCENARIO("Local media repository rejects oversized media and removes stored references",
         "[media][repository]")
{
    GIVEN("a configured local media repository")
    {
        auto repository = test_repository();

        WHEN("an oversized upload and a removed media record are requested")
        {
            auto const oversized = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "0123456789abcdefg", true});
            auto const uploaded = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "small", true});
            auto const removed = merovingian::media::remove_local_media(
                repository, uploaded.media_id, "retention expired");
            auto const after_remove = merovingian::media::download_local_media(
                repository, "example.org", uploaded.media_id);

            THEN("oversized uploads fail closed and removed bytes are no longer served")
            {
                REQUIRE_FALSE(oversized.ok);
                REQUIRE(oversized.reason == "media upload exceeds size limit");
                REQUIRE(repository.metrics.uploads_rejected == 1U);
                REQUIRE(uploaded.ok);
                REQUIRE(removed.ok);
                REQUIRE(repository.blobs.front().ref_count == 0U);
                REQUIRE(repository.blobs.front().bytes.empty());
                REQUIRE_FALSE(after_remove.ok);
                REQUIRE(after_remove.status == 404U);
            }
        }
    }
}

SCENARIO("Local media repository does not deduplicate against removed zero-reference blobs",
         "[media][repository]")
{
    GIVEN("a configured local media repository with removed media")
    {
        auto repository = test_repository();

        WHEN("the same bytes are uploaded after their previous record is removed")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "reupload", true});
            auto const removed = merovingian::media::remove_local_media(repository, first.media_id,
                                                                        "retention expired");
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org",
                {"@alice:example.org", "text/plain", "text/plain", "reupload", true});
            auto const downloaded = merovingian::media::download_local_media(
                repository, "example.org", second.media_id);

            THEN("a new live blob is created and downloads return the original bytes")
            {
                REQUIRE(first.ok);
                REQUIRE(removed.ok);
                REQUIRE(second.ok);
                REQUIRE_FALSE(second.deduplicated);
                REQUIRE(repository.blobs.size() == 2U);
                REQUIRE(repository.blobs.front().ref_count == 0U);
                REQUIRE(repository.blobs.back().ref_count == 1U);
                REQUIRE(downloaded.ok);
                REQUIRE(downloaded.bytes == "reupload");
            }
        }
    }
}

SCENARIO("Remote media fetches fail closed for the MVP", "[media][repository][remote]")
{
    GIVEN("remote media is disabled")
    {
        auto repository = test_repository();

        WHEN("a remote media fetch is requested")
        {
            auto const result = merovingian::media::fetch_remote_media_disabled(
                repository,
                {"remote.example.org", "media123", "remote.example.org", {"203.0.113.20"}});

            THEN("the fetch is explicitly rejected and counted")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 502U);
                REQUIRE(result.reason == "remote media fetch disabled");
                REQUIRE(repository.metrics.remote_fetch_rejections == 1U);
            }
        }
    }
}
