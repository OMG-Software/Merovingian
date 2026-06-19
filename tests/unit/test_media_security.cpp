// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/security.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace
{

[[nodiscard]] auto default_upload_policy() -> merovingian::media::MediaUploadPolicy
{
    return {
        1024U, {"image/png", "image/jpeg", "text/plain"},
         true, true, true,
    };
}

} // namespace

SCENARIO("Media upload policy enforces size, MIME, sniffing, scanner, quarantine, and hash requirements",
         "[media][security][upload]")
{
    GIVEN("a media upload policy and representative upload requests")
    {
        auto const policy = default_upload_policy();
        auto valid = merovingian::media::MediaUploadRequest{};
        valid.byte_size = 512U;
        valid.declared_mime_type = "image/png";
        valid.sniffed_mime_type = "image/png";
        valid.content_hash = "sha256:abc";
        valid.scanner_clean = true;

        auto oversized = valid;
        oversized.byte_size = 2048U;
        auto mismatched_mime = valid;
        mismatched_mime.sniffed_mime_type = "text/plain";
        auto unknown_mime = valid;
        unknown_mime.declared_mime_type = "application/x-unknown";
        unknown_mime.sniffed_mime_type = "application/x-unknown";
        auto scanner_failure = valid;
        scanner_failure.scanner_clean = false;
        auto missing_hash = valid;
        missing_hash.content_hash.clear();

        WHEN("uploads are evaluated")
        {
            auto const accepted = merovingian::media::evaluate_media_upload(policy, valid);
            auto const rejected_size = merovingian::media::evaluate_media_upload(policy, oversized);
            auto const quarantined_mime_mismatch = merovingian::media::evaluate_media_upload(policy, mismatched_mime);
            auto const quarantined_unknown_mime = merovingian::media::evaluate_media_upload(policy, unknown_mime);
            auto const quarantined_scanner = merovingian::media::evaluate_media_upload(policy, scanner_failure);
            auto const quarantined_missing_hash = merovingian::media::evaluate_media_upload(policy, missing_hash);

            THEN("only safe uploads are accepted and ambiguous uploads are quarantined")
            {
                REQUIRE(accepted.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(rejected_size.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_size.reason == "media upload exceeds size limit");
                REQUIRE(quarantined_mime_mismatch.disposition == merovingian::media::MediaDisposition::quarantine);
                REQUIRE(quarantined_mime_mismatch.reason == "declared MIME type does not match content");
                REQUIRE(quarantined_unknown_mime.disposition == merovingian::media::MediaDisposition::quarantine);
                REQUIRE(quarantined_scanner.disposition == merovingian::media::MediaDisposition::quarantine);
                REQUIRE(quarantined_missing_hash.disposition == merovingian::media::MediaDisposition::quarantine);
            }
        }
    }
}

SCENARIO("Remote media fetch policy isolates remotes and blocks private addresses", "[media][security][remote]")
{
    GIVEN("remote media fetch requests")
    {
        auto valid = merovingian::media::RemoteMediaFetchRequest{};
        valid.origin_server = "media.example.org";
        valid.media_id = "abc123";
        valid.resolved_host = "media.example.org";
        valid.resolved_addresses = {"203.0.113.15"};
        valid.isolate_remote_media = true;
        valid.private_address_fetches_blocked = true;

        auto private_address = valid;
        private_address.resolved_addresses = {"127.0.0.1"};
        auto not_isolated = valid;
        not_isolated.isolate_remote_media = false;
        auto unsafe_id = valid;
        unsafe_id.media_id = "../secret";

        WHEN("remote media fetch policy is evaluated")
        {
            auto const accepted = merovingian::media::remote_media_fetch_policy(valid);
            auto const rejected_private = merovingian::media::remote_media_fetch_policy(private_address);
            auto const rejected_isolation = merovingian::media::remote_media_fetch_policy(not_isolated);
            auto const rejected_id = merovingian::media::remote_media_fetch_policy(unsafe_id);

            THEN("only isolated public remote fetches are accepted")
            {
                REQUIRE(accepted.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(rejected_private.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_private.reason == "remote media address is private or loopback");
                REQUIRE(rejected_isolation.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_isolation.reason == "remote media isolation is required");
                REQUIRE(rejected_id.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_id.reason == "invalid remote media id");
            }
        }
    }
}

SCENARIO("Remote media fetch policy blocks 172.16/12 and IPv6 private ranges and allows public 172.1",
         "[media][security][remote][ssrf]")
{
    GIVEN("remote media fetch requests resolved to private and public addresses")
    {
        auto base = merovingian::media::RemoteMediaFetchRequest{};
        base.origin_server = "media.example.org";
        base.media_id = "abc123";
        base.resolved_host = "media.example.org";
        base.isolate_remote_media = true;
        base.private_address_fetches_blocked = true;

        auto rfc1918_172 = base;
        rfc1918_172.resolved_addresses = {"172.16.0.1"};
        auto rfc1918_172_high = base;
        rfc1918_172_high.resolved_addresses = {"172.31.255.255"};
        auto public_172 = base;
        public_172.resolved_addresses = {"172.1.0.1"};
        auto link_local_v6 = base;
        link_local_v6.resolved_addresses = {"fe80::1"};
        auto ula_v6 = base;
        ula_v6.resolved_addresses = {"fc00::1"};
        auto v4_mapped_private = base;
        v4_mapped_private.resolved_addresses = {"::ffff:127.0.0.1"};

        WHEN("the consolidated private/loopback filter is applied")
        {
            auto const blocked_172 = merovingian::media::remote_media_fetch_policy(rfc1918_172);
            auto const blocked_172_high = merovingian::media::remote_media_fetch_policy(rfc1918_172_high);
            auto const allowed_public_172 = merovingian::media::remote_media_fetch_policy(public_172);
            auto const blocked_link_local = merovingian::media::remote_media_fetch_policy(link_local_v6);
            auto const blocked_ula = merovingian::media::remote_media_fetch_policy(ula_v6);
            auto const blocked_mapped = merovingian::media::remote_media_fetch_policy(v4_mapped_private);

            THEN("172.16/12, IPv6 link-local, ULA, and IPv4-mapped private are rejected and public 172.1 is allowed")
            {
                REQUIRE(blocked_172.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(blocked_172.reason == "remote media address is private or loopback");
                REQUIRE(blocked_172_high.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(allowed_public_172.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(blocked_link_local.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(blocked_ula.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(blocked_mapped.disposition == merovingian::media::MediaDisposition::reject);
            }
        }
    }
}

SCENARIO("Sandboxed media worker plans require hardened isolation controls", "[media][security][worker]")
{
    GIVEN("hardened and weakened worker plans")
    {
        auto hardened = merovingian::media::SandboxedMediaWorkerPlan{};
        auto networked = hardened;
        networked.network_disabled = false;
        auto no_limit = hardened;
        no_limit.memory_limit_bytes = 0U;

        WHEN("worker plans are evaluated")
        {
            auto const hardened_ok = merovingian::media::sandboxed_worker_plan_is_hardened(hardened);
            auto const networked_ok = merovingian::media::sandboxed_worker_plan_is_hardened(networked);
            auto const no_limit_ok = merovingian::media::sandboxed_worker_plan_is_hardened(no_limit);

            THEN("only fully isolated workers are hardened")
            {
                REQUIRE(hardened_ok);
                REQUIRE_FALSE(networked_ok);
                REQUIRE_FALSE(no_limit_ok);
            }
        }
    }
}

SCENARIO("Decoder safety policy rejects unsafe decoders and excessive expansion", "[media][security][decoder]")
{
    GIVEN("decoder safety policy and requests")
    {
        auto const policy = merovingian::media::DecoderSafetyPolicy{1024U, 65536U, 1000000U, 10U, 50U, true};
        auto safe = merovingian::media::DecoderSafetyRequest{512U, 4096U, 40000U, 1U, true};
        auto unsafe_decoder = safe;
        unsafe_decoder.decoder_marked_safe = false;
        auto too_large_output = safe;
        too_large_output.estimated_output_bytes = 131072U;
        auto excessive_ratio = safe;
        excessive_ratio.estimated_output_bytes = std::uint64_t{512U} * 51U;
        auto too_many_frames = safe;
        too_many_frames.animation_frames = 11U;

        WHEN("decoder safety is evaluated")
        {
            auto const accepted = merovingian::media::evaluate_decoder_safety(policy, safe);
            auto const rejected_decoder = merovingian::media::evaluate_decoder_safety(policy, unsafe_decoder);
            auto const rejected_output = merovingian::media::evaluate_decoder_safety(policy, too_large_output);
            auto const rejected_ratio = merovingian::media::evaluate_decoder_safety(policy, excessive_ratio);
            auto const rejected_frames = merovingian::media::evaluate_decoder_safety(policy, too_many_frames);

            THEN("unsafe or suspicious decoder work is rejected")
            {
                REQUIRE(accepted.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(rejected_decoder.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_decoder.reason == "decoder is not allowed");
                REQUIRE(rejected_output.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_output.reason == "decoded output exceeds limit");
                REQUIRE(rejected_ratio.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_ratio.reason == "decoded output expansion ratio exceeds limit");
                REQUIRE(rejected_frames.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(rejected_frames.reason == "animation frame count exceeds limit");
            }
        }
    }
}

SCENARIO("Media deduplication keys and admin quarantine actions are validated", "[media][security][quarantine]")
{
    GIVEN("deduplication keys and admin quarantine requests")
    {
        auto const key = merovingian::media::make_media_deduplication_key("sha256", "abcdef", 128U);
        auto const invalid_key = merovingian::media::make_media_deduplication_key("sha256", "", 128U);
        auto quarantine = merovingian::media::AdminQuarantineRequest{};
        quarantine.action = merovingian::media::AdminQuarantineAction::quarantine;
        quarantine.admin_user_id = "@admin:example.org";
        quarantine.media_id = "media123";
        quarantine.reason = "policy violation";
        auto missing_reason = quarantine;
        missing_reason.reason.clear();
        auto release = quarantine;
        release.action = merovingian::media::AdminQuarantineAction::release;
        release.reason.clear();

        WHEN("deduplication and admin quarantine policies are evaluated")
        {
            auto const valid_key = merovingian::media::media_deduplication_key_is_valid(key);
            auto const invalid_key_ok = merovingian::media::media_deduplication_key_is_valid(invalid_key);
            auto const quarantine_decision = merovingian::media::admin_quarantine_policy(quarantine);
            auto const missing_reason_decision = merovingian::media::admin_quarantine_policy(missing_reason);
            auto const release_decision = merovingian::media::admin_quarantine_policy(release);

            THEN("valid keys/actions pass and unsafe admin actions fail closed")
            {
                REQUIRE(valid_key);
                REQUIRE_FALSE(invalid_key_ok);
                REQUIRE(quarantine_decision.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(missing_reason_decision.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(missing_reason_decision.reason == "quarantine reason is required");
                REQUIRE(release_decision.disposition == merovingian::media::MediaDisposition::accept);
            }
        }
    }
}

SCENARIO("Media security boundary notes document remote isolation, decoder limits, and quarantine", "[media][security]")
{
    GIVEN("media security boundary notes")
    {
        WHEN("notes are returned")
        {
            auto const notes = merovingian::media::media_security_boundary_notes();

            THEN("all hardening boundaries are documented")
            {
                REQUIRE(notes.size() == 4U);
                REQUIRE(notes[0].find("Remote media") != std::string::npos);
                REQUIRE(notes[1].find("sandboxed worker") != std::string::npos);
                REQUIRE(notes[2].find("Expansion") != std::string::npos);
                REQUIRE(notes[3].find("Quarantine") != std::string::npos);
            }
        }
    }
}
