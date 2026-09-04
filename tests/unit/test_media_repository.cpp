// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/repository.hpp"

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

SCENARIO("Local media repository uploads, downloads, and deduplicates safe media", "[media][repository]")
{
    GIVEN("a configured local media repository")
    {
        auto repository = test_repository();

        WHEN("the same safe content is uploaded twice")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "hello", true});
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "hello", true});
            auto const downloaded = merovingian::media::download_local_media(repository, "example.org", first.media_id);

            THEN("two media records reference one stored blob and bytes are served safely")
            {
                REQUIRE(first.ok);
                REQUIRE(first.hash_algorithm == "blake2b");
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
                repository, "example.org", {"@alice:example.org", "image/png", "image/png", "png-bytes", false});
            auto const blocked = merovingian::media::download_local_media(repository, "example.org", uploaded.media_id);
            auto const released = merovingian::media::release_local_media(repository, uploaded.media_id);
            auto const downloaded =
                merovingian::media::download_local_media(repository, "example.org", uploaded.media_id);

            THEN("quarantined media cannot be served until an admin release")
            {
                REQUIRE(uploaded.ok);
                REQUIRE(uploaded.quarantined);
                REQUIRE(repository.metrics.uploads_quarantined == 1U);
                REQUIRE(repository.thumbnails.empty());
                REQUIRE_FALSE(blocked.ok);
                REQUIRE(blocked.status == 451U);
                REQUIRE(released.ok);
                REQUIRE(downloaded.ok);
                REQUIRE(downloaded.bytes == "png-bytes");
            }
        }
    }
}

SCENARIO("Local media repository rejects oversized media and removes stored references", "[media][repository]")
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
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "small", true});
            auto const removed =
                merovingian::media::remove_local_media(repository, uploaded.media_id, "retention expired");
            auto const after_remove =
                merovingian::media::download_local_media(repository, "example.org", uploaded.media_id);

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

SCENARIO("Local media repository does not deduplicate against removed zero-reference blobs", "[media][repository]")
{
    GIVEN("a configured local media repository with removed media")
    {
        auto repository = test_repository();

        WHEN("the same bytes are uploaded after their previous record is removed")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "reupload", true});
            auto const removed =
                merovingian::media::remove_local_media(repository, first.media_id, "retention expired");
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "reupload", true});
            auto const downloaded =
                merovingian::media::download_local_media(repository, "example.org", second.media_id);

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
                repository, {"remote.example.org", "media123", "remote.example.org", {"203.0.113.20"}});

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

SCENARIO("Remote media fetch stores fetched bytes only after policy and processing boundaries pass",
         "[media][repository][remote]")
{
    GIVEN("remote media fetching is enabled with sandboxed processing")
    {
        auto repository = test_repository();
        repository.config.remote_fetch_enabled = true;
        // This scenario is about the scanner/decoder boundary, not the
        // acceptance-policy feature (see the dedicated
        // "Remote fetch acceptance policy" scenario below) — opt into
        // allow_after_scan explicitly rather than relying on the
        // fail-closed quarantine default for remote-fetched media.
        repository.config.remote_fetch_media_policy = merovingian::media::MediaAcceptancePolicy::allow_after_scan;

        WHEN("safe remote content and unsafe decoder work are requested")
        {
            // Real PNG magic bytes are required here: the repository now sniffs the
            // actual content and quarantines uploads whose declared MIME type doesn't
            // match (see media/security.hpp sniff_mime_type) — a literal "png-bytes"
            // string sniffs as text/plain and would be quarantined, not accepted.
            // Kept to the PNG signature alone (8 bytes) — test_repository() caps
            // max_upload_bytes at 16, and any trailing payload counts against it.
            auto const png_bytes = std::string{"\x89PNG\r\n\x1a\n", 8U};
            auto const fetched = merovingian::media::fetch_remote_media(repository, {"remote.example.org",
                                                                                     "media123",
                                                                                     "remote.example.org",
                                                                                     {"203.0.113.20"},
                                                                                     "image/png",
                                                                                     png_bytes,
                                                                                     true,
                                                                                     16U,
                                                                                     64U,
                                                                                     1U,
                                                                                     true});
            auto const unsafe_decoder = merovingian::media::fetch_remote_media(repository, {"remote.example.org",
                                                                                            "media124",
                                                                                            "remote.example.org",
                                                                                            {"203.0.113.20"},
                                                                                            "image/png",
                                                                                            png_bytes,
                                                                                            true,
                                                                                            2048U,
                                                                                            64U,
                                                                                            1U,
                                                                                            false});

            THEN("accepted remote media is durable-repository ready and unsafe processing fails closed")
            {
                REQUIRE(fetched.ok);
                REQUIRE(fetched.status == 200U);
                REQUIRE(fetched.content_type == "image/png");
                REQUIRE(fetched.bytes == png_bytes);
                REQUIRE(fetched.hash_algorithm == "blake2b");
                REQUIRE_FALSE(fetched.storage_id.empty());
                REQUIRE(repository.records.size() == 1U);
                REQUIRE(repository.blobs.size() == 1U);
                REQUIRE(repository.thumbnails.size() == 1U);
                REQUIRE(repository.metrics.remote_fetches_accepted == 1U);
                REQUIRE(repository.metrics.thumbnails_generated == 1U);
                REQUIRE_FALSE(unsafe_decoder.ok);
                REQUIRE(unsafe_decoder.reason == "decoder is not allowed");
                REQUIRE(repository.metrics.processing_rejections == 1U);
            }
        }
    }
}

// Security audit finding: fetch_remote_media_live() fabricated
// scanner_clean=true for every federated fetch, so remote-fetched bytes were
// always treated as scanner-clean regardless of RuntimeMediaConfig's
// acceptance policy. RuntimeMediaConfig::remote_fetch_media_policy defaults
// to quarantine (unlike local_upload_policy's allow-after-scan default)
// specifically because remote media has no accountable local uploader and no
// real scanner verdict is ever produced for it today.
SCENARIO("Remote-fetched media is quarantined by the default acceptance policy even when reported scanner-clean",
         "[media][repository][remote][security]")
{
    GIVEN("a repository using RuntimeMediaConfig's default acceptance policies")
    {
        auto repository = test_repository();
        repository.config.remote_fetch_enabled = true;
        REQUIRE(repository.config.remote_fetch_media_policy == merovingian::media::MediaAcceptancePolicy::quarantine);
        REQUIRE(repository.config.local_upload_policy == merovingian::media::MediaAcceptancePolicy::allow_after_scan);

        WHEN("a remote fetch reports scanner_clean=true, exactly as fetch_remote_media_live() would if it "
             "fabricated the verdict")
        {
            auto const fetched = merovingian::media::fetch_remote_media(repository, {"remote.example.org",
                                                                                     "media999",
                                                                                     "remote.example.org",
                                                                                     {"203.0.113.20"},
                                                                                     "image/png",
                                                                                     "png-bytes",
                                                                                     true,
                                                                                     16U,
                                                                                     64U,
                                                                                     1U,
                                                                                     true});

            THEN("the bytes are still quarantined rather than served, because the acceptance policy overrides it")
            {
                REQUIRE(fetched.ok);
                REQUIRE(fetched.quarantined);
                REQUIRE(repository.records.front().state == merovingian::media::LocalMediaState::quarantined);
            }
        }

        WHEN("a local upload with an identical scanner-clean verdict is made")
        {
            auto request = merovingian::media::LocalMediaUploadRequest{};
            request.owner_user_id = "@alice:example.org";
            request.declared_mime_type = "text/plain";
            request.sniffed_mime_type = "text/plain";
            request.bytes = "hello";
            request.scanner_clean = true;
            auto const uploaded = merovingian::media::upload_local_media(repository, "example.org", request);

            THEN("it is accepted, since local_upload_policy defaults to allow-after-scan, not quarantine")
            {
                REQUIRE(uploaded.ok);
                REQUIRE_FALSE(uploaded.quarantined);
            }
        }
    }
}

SCENARIO("Local media processing rejects decompression bombs before blob storage", "[media][repository]")
{
    GIVEN("a repository with strict decoder limits")
    {
        auto repository = test_repository();

        WHEN("an upload estimates excessive decoded output")
        {
            auto request = merovingian::media::LocalMediaUploadRequest{
                "@alice:example.org", "image/png", "image/png", "png-bytes", true, 2048U, 64U, 1U, true};
            auto const rejected = merovingian::media::upload_local_media(repository, "example.org", request);

            THEN("the upload fails closed and no blob is retained")
            {
                REQUIRE_FALSE(rejected.ok);
                REQUIRE(rejected.status == 413U);
                REQUIRE(rejected.reason == "decoded output exceeds limit");
                REQUIRE(repository.blobs.empty());
                REQUIRE(repository.records.empty());
                REQUIRE(repository.metrics.processing_rejections == 1U);
            }
        }
    }
}

// --- 0.12.5 security audit, finding 8 ----------------------------------------
//
// build_federation_media_download_body() hardcoded "Content-Disposition: inline"
// for every content type, so a peer's clients were told to render whatever we
// served -- an executable, a scripted HTML document -- inline in the media
// origin's context, bypassing the inline-safe allow-list the local download path
// applies. Spec: CS API section "Serving inline content".

SCENARIO("Federation media download derives Content-Disposition from the inline-safe allow-list",
         "[media][repository][federation][security]")
{
    GIVEN("a non-inline-safe content type")
    {
        auto const content_type = std::string{"application/x-msdownload"};

        WHEN("the federation download body is built")
        {
            auto const envelope = merovingian::media::build_federation_media_download_body(content_type, "MZ-bytes");

            THEN("the media part is marked as an attachment, not inline")
            {
                REQUIRE(envelope.body.find("Content-Disposition: attachment") != std::string::npos);
                REQUIRE(envelope.body.find("Content-Disposition: inline") == std::string::npos);
            }
        }
    }

    GIVEN("no declared content type at all")
    {
        WHEN("the federation download body is built")
        {
            auto const envelope = merovingian::media::build_federation_media_download_body({}, "unknown-bytes");

            THEN("it falls back to application/octet-stream and fails closed to attachment")
            {
                REQUIRE(envelope.body.find("Content-Type: application/octet-stream") != std::string::npos);
                REQUIRE(envelope.body.find("Content-Disposition: attachment") != std::string::npos);
            }
        }
    }

    GIVEN("an inline-safe content type carrying a charset parameter")
    {
        WHEN("the federation download body is built")
        {
            auto const envelope =
                merovingian::media::build_federation_media_download_body("text/plain; charset=utf-8", "hello");

            THEN("it is served inline: the parameter must not defeat the allow-list match")
            {
                REQUIRE(envelope.body.find("Content-Disposition: inline") != std::string::npos);
            }
        }
    }

    GIVEN("a type that merely has an inline-safe type as a prefix")
    {
        WHEN("the federation download body is built")
        {
            auto const envelope =
                merovingian::media::build_federation_media_download_body("text/plain-evil", "payload");

            THEN("it is served as an attachment: a prefix must not pass the allow-list")
            {
                REQUIRE(envelope.body.find("Content-Disposition: attachment") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation media download body is a valid multipart/mixed envelope", "[media][repository][federation]")
{
    GIVEN("a media content type and raw bytes")
    {
        auto const content_type = std::string{"image/png"};
        auto const bytes = std::string{"png-bytes"};

        WHEN("the v1.19 federation download body is built")
        {
            auto const envelope = merovingian::media::build_federation_media_download_body(content_type, bytes);

            THEN("the outer Content-Type is multipart/mixed with a boundary and the body has two parseable parts")
            {
                REQUIRE_FALSE(envelope.body.empty());
                REQUIRE(envelope.content_type.starts_with("multipart/mixed; boundary="));
                auto const boundary_pos = envelope.content_type.find("boundary=");
                REQUIRE(boundary_pos != std::string::npos);
                auto const boundary = envelope.content_type.substr(boundary_pos + 9U);
                REQUIRE_FALSE(boundary.empty());

                auto const expected = std::string{"--"} + boundary + "\r\n" +
                                      "Content-Type: application/json\r\n\r\n{}\r\n" + "--" + boundary +
                                      "\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\n\r\n" + bytes +
                                      "\r\n--" + boundary + "--\r\n";
                REQUIRE(envelope.body == expected);
            }
        }
    }
}

// --- 0.12.5 security audit, finding 19 ---------------------------------------
//
// upload_local_media() pushed every accepted blob into an in-memory vector with
// no cap on total records, total bytes, or per-user quota, and fetch_remote_media
// reused the same path. Upload spam — or a large remote media cache — grew the
// repository until the process was OOM-killed.

SCENARIO("Local media repository refuses uploads past its record cap", "[media][repository][security]")
{
    GIVEN("a repository configured to hold at most two media records")
    {
        auto repository = test_repository();
        repository.config.max_records = 2U;

        WHEN("a third distinct upload is attempted")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "one", true});
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "two", true});
            auto const third = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "three", true});

            THEN("the uploads within the cap succeed and the one past it is refused")
            {
                REQUIRE(first.ok);
                REQUIRE(second.ok);
                REQUIRE_FALSE(third.ok);
                REQUIRE(third.status == 507U);
            }

            THEN("the refused upload stores nothing, so memory stays bounded")
            {
                REQUIRE(repository.records.size() == 2U);
                REQUIRE(repository.blobs.size() == 2U);
            }
        }
    }
}

SCENARIO("Local media repository refuses uploads past its total byte cap", "[media][repository][security]")
{
    GIVEN("a repository configured to hold at most eight bytes of media")
    {
        auto repository = test_repository();
        repository.config.max_total_bytes = 8U;

        WHEN("uploads exceed the total byte budget")
        {
            auto const first = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "12345", true});
            auto const second = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "67890", true});

            THEN("the upload that would cross the budget is refused and nothing is stored for it")
            {
                REQUIRE(first.ok);
                REQUIRE_FALSE(second.ok);
                REQUIRE(second.status == 507U);
                REQUIRE(repository.blobs.size() == 1U);
            }
        }
    }
}

SCENARIO("Local media repository enforces a per-user byte quota", "[media][repository][security]")
{
    GIVEN("a repository with a per-user quota of eight bytes")
    {
        auto repository = test_repository();
        repository.config.max_bytes_per_user = 8U;

        WHEN("one user exceeds the quota and another user uploads within it")
        {
            auto const alice_first = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "12345", true});
            auto const alice_second = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "67890", true});
            auto const bob = merovingian::media::upload_local_media(
                repository, "example.org", {"@bob:example.org", "text/plain", "text/plain", "abcde", true});

            THEN("only the over-quota user is refused; the quota is per user, not global")
            {
                REQUIRE(alice_first.ok);
                REQUIRE_FALSE(alice_second.ok);
                REQUIRE(alice_second.status == 507U);
                REQUIRE(bob.ok);
            }
        }
    }
}

SCENARIO("Deduplicated uploads do not consume repository capacity twice", "[media][repository][security]")
{
    GIVEN("a repository at its byte cap holding one blob")
    {
        auto repository = test_repository();
        repository.config.max_total_bytes = 5U;
        auto const first = merovingian::media::upload_local_media(
            repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "12345", true});
        REQUIRE(first.ok);

        WHEN("the identical content is uploaded again")
        {
            auto const duplicate = merovingian::media::upload_local_media(
                repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", "12345", true});

            THEN("it is accepted, because deduplication stores no additional bytes")
            {
                REQUIRE(duplicate.ok);
                REQUIRE(duplicate.deduplicated);
                REQUIRE(repository.blobs.size() == 1U);
            }
        }
    }
}

SCENARIO("An uncapped media repository keeps its previous unbounded behaviour", "[media][repository][security]")
{
    GIVEN("a repository with every capacity limit left at its disabled default")
    {
        auto repository = test_repository();
        REQUIRE(repository.config.max_records == 0U);
        REQUIRE(repository.config.max_total_bytes == 0U);
        REQUIRE(repository.config.max_bytes_per_user == 0U);

        WHEN("several distinct uploads are made")
        {
            auto accepted = 0U;
            for (auto const* body : {"a1", "a2", "a3", "a4", "a5"})
            {
                if (merovingian::media::upload_local_media(
                        repository, "example.org", {"@alice:example.org", "text/plain", "text/plain", body, true})
                        .ok)
                {
                    ++accepted;
                }
            }

            THEN("all of them are accepted")
            {
                REQUIRE(accepted == 5U);
            }
        }
    }
}
