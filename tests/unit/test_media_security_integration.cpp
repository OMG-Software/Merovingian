// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/security.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Integrated media repository policy accepts only fully safe media flow", "[media][security][integration]")
{
    GIVEN("a complete local media processing flow")
    {
        auto const upload_policy = merovingian::media::MediaUploadPolicy{
            1048576U,
            {"image/png"},
            true,
            true,
            true,
        };
        auto const upload = merovingian::media::MediaUploadRequest{
            4096U,
            "image/png",
            "image/png",
            "sha256:0123456789abcdef",
            true,
        };
        auto const worker = merovingian::media::SandboxedMediaWorkerPlan{};
        auto const decoder_policy = merovingian::media::DecoderSafetyPolicy{1048576U, 16777216U, 4096000U, 1U, 64U, true};
        auto const decoder = merovingian::media::DecoderSafetyRequest{4096U, 65536U, 65536U, 1U, true};
        auto const dedupe = merovingian::media::make_media_deduplication_key("sha256", "0123456789abcdef", upload.byte_size);

        WHEN("each boundary decision is evaluated")
        {
            auto const upload_decision = merovingian::media::evaluate_media_upload(upload_policy, upload);
            auto const worker_decision = merovingian::media::sandboxed_worker_plan_is_hardened(worker);
            auto const decoder_decision = merovingian::media::evaluate_decoder_safety(decoder_policy, decoder);
            auto const dedupe_decision = merovingian::media::media_deduplication_key_is_valid(dedupe);

            THEN("the full flow is accepted")
            {
                REQUIRE(upload_decision.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(worker_decision);
                REQUIRE(decoder_decision.disposition == merovingian::media::MediaDisposition::accept);
                REQUIRE(dedupe_decision);
            }
        }
    }
}

SCENARIO("Integrated media repository policy rejects unsafe remote media flow", "[media][security][integration]")
{
    GIVEN("a remote media flow targeting a private address and unsafe decoder")
    {
        auto const remote = merovingian::media::RemoteMediaFetchRequest{
            "media.example.org",
            "media123",
            "media.example.org",
            {"192.168.1.20"},
            true,
            true,
        };
        auto const decoder_policy = merovingian::media::DecoderSafetyPolicy{1048576U, 16777216U, 4096000U, 1U, 64U, true};
        auto const decoder = merovingian::media::DecoderSafetyRequest{4096U, 65536U, 65536U, 1U, false};
        auto const admin_action = merovingian::media::AdminQuarantineRequest{
            merovingian::media::AdminQuarantineAction::quarantine,
            "@admin:example.org",
            "media123",
            "remote fetch rejected",
        };

        WHEN("each boundary decision is evaluated")
        {
            auto const remote_decision = merovingian::media::remote_media_fetch_policy(remote);
            auto const decoder_decision = merovingian::media::evaluate_decoder_safety(decoder_policy, decoder);
            auto const admin_decision = merovingian::media::admin_quarantine_policy(admin_action);

            THEN("unsafe remote fetches and decoders fail closed while admin quarantine remains available")
            {
                REQUIRE(remote_decision.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(remote_decision.reason == "remote media address is private or loopback");
                REQUIRE(decoder_decision.disposition == merovingian::media::MediaDisposition::reject);
                REQUIRE(decoder_decision.reason == "decoder is not allowed");
                REQUIRE(admin_decision.disposition == merovingian::media::MediaDisposition::accept);
            }
        }
    }
}
