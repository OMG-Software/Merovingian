// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/media/security.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto media_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    security.media.max_upload_size = "8B";
    security.media.quarantine_unknown_mime = false;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto media_id_from_upload_response(std::string_view body) -> std::string
{
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(body.starts_with(prefix));
    auto const after_prefix = body.substr(prefix.size());
    auto const separator = after_prefix.find('|');
    REQUIRE(separator != std::string_view::npos);
    return std::string{after_prefix.substr(0U, separator)};
}

[[nodiscard]] auto register_and_login_admin(merovingian::homeserver::HomeserverRuntime& runtime)
    -> std::string
{
    auto const registration = merovingian::homeserver::handle_local_http_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"});
    REQUIRE(registration.status == 200U);

    auto const login = merovingian::homeserver::handle_local_http_request(
        runtime,
        {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
    REQUIRE(login.status == 200U);
    return login.body;
}

} // namespace

SCENARIO("Integrated local media repository flow covers upload download dedupe quarantine release "
         "remove and metrics",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with media upload limits")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("local media is uploaded and administered through HTTP routes")
        {
            auto const first_upload = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            auto const first_media_id = media_id_from_upload_response(first_upload.body);
            auto const duplicate_upload = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|clean|hello"});
            auto const download = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/media/v3/download/example.org/" + first_media_id, {}, {}});
            auto const quarantine = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/quarantine/" + first_media_id, token,
                          "policy review"});
            auto const blocked_download = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/media/v3/download/example.org/" + first_media_id, {}, {}});
            auto const release = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_merovingian/admin/media/release/" + first_media_id, token, {}});
            auto const released_download = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/media/v3/download/example.org/" + first_media_id, {}, {}});
            auto const remove = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/remove/" + first_media_id, token,
                          "operator removal"});
            auto const removed_download = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/media/v3/download/example.org/" + first_media_id, {}, {}});
            auto const metrics = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/media/metrics", token, {}});

            THEN("media bytes are served only while available and metadata/audit paths are updated")
            {
                REQUIRE(first_upload.status == 200U);
                REQUIRE(first_upload.body.find("deduplicated=false") != std::string::npos);
                REQUIRE(duplicate_upload.status == 200U);
                REQUIRE(duplicate_upload.body.find("deduplicated=true") != std::string::npos);
                REQUIRE(download.status == 200U);
                REQUIRE(download.body == "text/plain|hello");
                REQUIRE(quarantine.status == 200U);
                REQUIRE(blocked_download.status == 451U);
                REQUIRE(blocked_download.body == "media is quarantined");
                REQUIRE(release.status == 200U);
                REQUIRE(released_download.status == 200U);
                REQUIRE(remove.status == 200U);
                REQUIRE(removed_download.status == 404U);
                REQUIRE(runtime.media_repository.blobs.size() == 1U);
                REQUIRE(runtime.media_repository.blobs.front().ref_count == 1U);
                REQUIRE(runtime.database.persistent_store.local_media.size() == 2U);
                REQUIRE(runtime.database.persistent_store.admin_actions.size() == 3U);
                REQUIRE(std::ranges::any_of(runtime.database.persistent_store.audit_log,
                                            [](auto const& event)
                                            {
                                                return event.category == "moderation" &&
                                                       event.event_type == "media.quarantined";
                                            }));
                REQUIRE(metrics.status == 200U);
                REQUIRE(metrics.body.find("media_uploads_accepted_total=2") != std::string::npos);
                REQUIRE(metrics.body.find("media_deduplicated_uploads_total=1") !=
                        std::string::npos);
                REQUIRE(metrics.body.find("media_admin_removals_total=1") != std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated media upload rejects oversized and unknown MIME uploads",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with strict media policy")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("unsafe uploads are submitted")
        {
            auto const oversized = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token,
                          "text/plain|text/plain|clean|too-large"});
            auto const unknown_mime = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/media/v3/upload", token,
                          "application/x-evil|application/x-evil|clean|evil"});
            auto const scanner_failure = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/media/v3/upload", token, "text/plain|text/plain|dirty|clean"});

            THEN("oversized and unknown MIME uploads are rejected and scanner failures are "
                 "quarantined")
            {
                REQUIRE(oversized.status == 413U);
                REQUIRE(oversized.body == "media upload exceeds size limit");
                REQUIRE(unknown_mime.status == 415U);
                REQUIRE(unknown_mime.body == "media MIME type is not allowed");
                REQUIRE(scanner_failure.status == 202U);
                REQUIRE(scanner_failure.body.find("quarantined=true") != std::string::npos);
                REQUIRE(runtime.media_repository.metrics.uploads_rejected == 2U);
                REQUIRE(runtime.media_repository.metrics.uploads_quarantined == 1U);
            }
        }
    }
}

SCENARIO("Remote media download route fails closed until a later milestone enables fetching",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with remote media disabled")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("a remote media download is requested")
        {
            auto const remote = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/media/v3/download/remote.example.org/media123", {}, {}});

            THEN("the request is explicitly rejected and audited")
            {
                REQUIRE(remote.status == 502U);
                REQUIRE(remote.body == "remote media fetch disabled");
                REQUIRE(runtime.media_repository.metrics.remote_fetch_rejections == 1U);
                REQUIRE(runtime.database.audit_events.back().event_type ==
                        "media.remote_fetch_rejected");
            }
        }
    }
}

SCENARIO("Integrated media routes preserve authentication and repository status codes",
         "[media][repository][integration]")
{
    GIVEN("a running homeserver with media upload limits")
    {
        auto started = merovingian::homeserver::start_runtime(media_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        auto const token = register_and_login_admin(runtime);

        WHEN("unauthenticated and missing-media requests reach media routes")
        {
            auto const unauthenticated_upload = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/media/v3/upload", {}, "text/plain|text/plain|clean|hello"});
            auto const missing_release = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/release/missing-media", token, {}});
            auto const unauthenticated_quarantine =
                merovingian::homeserver::handle_local_http_request(
                    runtime, {"POST",
                              "/_merovingian/admin/media/quarantine/missing-media",
                              {},
                              "policy review"});

            THEN("authentication failures and repository misses keep their status semantics")
            {
                REQUIRE(unauthenticated_upload.status == 401U);
                REQUIRE(unauthenticated_upload.body == "unauthenticated");
                REQUIRE(missing_release.status == 404U);
                REQUIRE(missing_release.body == "media not found");
                REQUIRE(unauthenticated_quarantine.status == 401U);
                REQUIRE(unauthenticated_quarantine.body == "admin authentication required");
            }
        }
    }
}

SCENARIO("Integrated media repository policy still rejects unsafe remote boundary inputs",
         "[media][security][integration]")
{
    GIVEN("a remote media flow targeting a private address and unsafe decoder")
    {
        auto const remote = merovingian::media::RemoteMediaFetchRequest{
            "media.example.org", "media123", "media.example.org", {"192.168.1.20"}, true, true,
        };
        auto const decoder_policy =
            merovingian::media::DecoderSafetyPolicy{1048576U, 16777216U, 4096000U, 1U, 64U, true};
        auto const decoder =
            merovingian::media::DecoderSafetyRequest{4096U, 65536U, 65536U, 1U, false};
        auto const admin_action = merovingian::media::AdminQuarantineRequest{
            merovingian::media::AdminQuarantineAction::quarantine,
            "@admin:example.org",
            "media123",
            "remote fetch rejected",
        };

        WHEN("each boundary decision is evaluated")
        {
            auto const remote_decision = merovingian::media::remote_media_fetch_policy(remote);
            auto const decoder_decision =
                merovingian::media::evaluate_decoder_safety(decoder_policy, decoder);
            auto const admin_decision = merovingian::media::admin_quarantine_policy(admin_action);

            THEN("unsafe remote fetches and decoders fail closed while admin quarantine remains "
                 "available")
            {
                REQUIRE(remote_decision.disposition ==
                        merovingian::media::MediaDisposition::reject);
                REQUIRE(remote_decision.reason == "remote media address is private or loopback");
                REQUIRE(decoder_decision.disposition ==
                        merovingian::media::MediaDisposition::reject);
                REQUIRE(decoder_decision.reason == "decoder is not allowed");
                REQUIRE(admin_decision.disposition == merovingian::media::MediaDisposition::accept);
            }
        }
    }
}
