// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/media/LocalMediaBlob.hpp"
#include "merovingian/media/LocalMediaRecord.hpp"
#include "merovingian/media/LocalMediaRepository.hpp"
#include "merovingian/media/LocalMediaState.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace
{

[[nodiscard]] auto media_runtime_config(std::string server_name = "example.org") -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::move(server_name);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

// MED-5: a server name can be written with different case or with the default
// federation port. The media download/thumbnail paths must treat all of these
// as the local server rather than trying to fetch them remotely.
SCENARIO("media download canonicalises the local server name before routing", "[homeserver][media][security][med-5]")
{
    GIVEN("a runtime whose server name is example.org and an available local media record")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(media_runtime_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const media_id = std::string{"med5-local"};
        auto const storage_id = std::string{"med5-storage"};
        runtime.media_repository.records.push_back(
            merovingian::media::LocalMediaRecord{media_id,
                                                 "@owner:example.org",
                                                 "image/png",
                                                 12U,
                                                 "sha256",
                                                 "digest",
                                                 storage_id,
                                                 merovingian::media::LocalMediaState::available,
                                                 {},
                                                 false});
        // ADR-0119: the repository holds metadata; the bytes are in the store,
        // which for this memory-backed runtime is the database.
        runtime.media_repository.blobs.push_back(
            merovingian::media::LocalMediaBlob{storage_id, "sha256", "digest", 12U, 1U});
        runtime.database.persistent_store.media_blobs.push_back(
            merovingian::database::PersistentMediaBlob{storage_id, "sha256", "digest", 12U, "local-bytes-here", 1U});

        WHEN("download is requested with a case-variant of the local server name")
        {
            auto const result = merovingian::homeserver::download_local_media(runtime, "EXAMPLE.org", media_id);

            THEN("the local record is served")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
            }
        }

        WHEN("download is requested with the local server name and default federation port")
        {
            auto const result = merovingian::homeserver::download_local_media(runtime, "example.org:8448", media_id);

            THEN("the local record is served")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
            }
        }

        WHEN("download is requested with the local host name and a port other than the default")
        {
            // example.org:8449 is a different Matrix server name from
            // example.org; only the default federation port may be dropped.
            auto const result = merovingian::homeserver::download_local_media(runtime, "Example.Org:8449", media_id);

            THEN("it is treated as remote media and the local bytes are not served")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 404U);
                REQUIRE(result.value.find("local-bytes-here") == std::string::npos);
            }
        }

        WHEN("download is requested with a truly remote server name")
        {
            auto const result = merovingian::homeserver::download_local_media(runtime, "remote.example.org", media_id);

            THEN("the request is refused as remote media")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 404U);
            }
        }

        WHEN("thumbnail is requested with a case-variant of the local server name")
        {
            auto const rejections_before = runtime.media_repository.metrics.remote_fetch_rejections;
            auto const result = merovingian::homeserver::download_local_media_thumbnail(
                runtime, "EXAMPLE.org", media_id, 32U, 32U, merovingian::media::ThumbnailMethod::scale);

            THEN("the local record is used")
            {
                // No thumbnail worker is wired in this test, but the request must
                // have reached the local path, not the remote refusal path.
                REQUIRE(runtime.media_repository.metrics.remote_fetch_rejections == rejections_before);
            }
        }
    }
}

namespace
{

// The access token of a freshly registered, logged-in local user.
[[nodiscard]] auto media_uploader_token(merovingian::homeserver::HomeserverRuntime& runtime) -> std::string
{
    auto const user = merovingian::homeserver::register_local_user(runtime, "uploader", "CorrectHorse7!",
                                                                   merovingian::tests::registration_token);
    REQUIRE(user.ok);
    auto const login = merovingian::homeserver::login_local_user_by_id(runtime, user.value, "UPLOADER");
    REQUIRE(login.ok);
    return login.value;
}

[[nodiscard]] auto live_blob_references(merovingian::homeserver::HomeserverRuntime const& runtime) -> std::uint64_t
{
    auto total = std::uint64_t{0U};
    for (auto const& blob : runtime.media_repository.blobs)
    {
        total += blob.ref_count;
    }
    return total;
}

} // namespace

// DB-5 (security-audit-report-2026-09-29.md): an upload whose database write
// failed was still answered 200 with an mxc:// URI, and the media vanished at
// the next restart. The record and its blob are now written in one
// transaction, and a failed write leaves memory as it was before the upload.
SCENARIO("A media upload whose database write fails is refused and leaves no trace",
         "[homeserver][media][security][db-5]")
{
    GIVEN("a runtime with a logged-in user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(media_runtime_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = media_uploader_token(runtime);
        auto& store = runtime.database.persistent_store;

        WHEN("the blob write of a new upload fails")
        {
            merovingian::database::force_persist_failure_for_statement(store, "upsert_media_blob");
            auto const failed =
                merovingian::homeserver::upload_local_media(runtime, token, "text/plain", "text/plain", true, "hello");

            THEN("the upload is refused with 500 and no media ID")
            {
                REQUIRE_FALSE(failed.ok);
                REQUIRE(failed.status == 500U);
                REQUIRE(failed.value.find("mxc://") == std::string::npos);
            }

            THEN("neither the record nor the blob was kept, in memory or in the store")
            {
                REQUIRE(runtime.media_repository.records.empty());
                REQUIRE(live_blob_references(runtime) == 0U);
                REQUIRE(store.local_media.empty());
                REQUIRE(store.media_blobs.empty());
            }

            AND_WHEN("the same bytes are uploaded again with a working store")
            {
                auto const retried = merovingian::homeserver::upload_local_media(runtime, token, "text/plain",
                                                                                 "text/plain", true, "hello");

                THEN("it is stored once, with one blob reference, in memory and in the store")
                {
                    REQUIRE(retried.ok);
                    REQUIRE(runtime.media_repository.records.size() == 1U);
                    REQUIRE(live_blob_references(runtime) == 1U);
                    REQUIRE(store.local_media.size() == 1U);
                    REQUIRE(store.media_blobs.size() == 1U);
                    REQUIRE(store.media_blobs.front().ref_count == 1U);
                }
            }
        }

        WHEN("a deduplicated upload of stored bytes fails to be written")
        {
            auto const first =
                merovingian::homeserver::upload_local_media(runtime, token, "text/plain", "text/plain", true, "hello");
            REQUIRE(first.ok);
            merovingian::database::force_persist_failure_for_statement(store, "insert_media");
            auto const failed =
                merovingian::homeserver::upload_local_media(runtime, token, "text/plain", "text/plain", true, "hello");

            THEN("it is refused, and the shared blob keeps the one reference it had")
            {
                REQUIRE_FALSE(failed.ok);
                REQUIRE(failed.status == 500U);
                REQUIRE(runtime.media_repository.records.size() == 1U);
                REQUIRE(live_blob_references(runtime) == 1U);
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.media_blobs.front().ref_count == 1U);
            }

            THEN("the media uploaded first is still served")
            {
                // first.value is "mxc://example.org/<media_id>|<content type>|...".
                auto const prefix = std::string{"mxc://example.org/"};
                REQUIRE(first.value.starts_with(prefix));
                auto const media_id = first.value.substr(prefix.size(), first.value.find('|') - prefix.size());
                REQUIRE(merovingian::homeserver::download_local_media(runtime, "example.org", media_id).ok);
            }
        }
    }
}
