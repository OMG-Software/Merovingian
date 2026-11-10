// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// F-16 (security audit run 4): POST /_matrix/media/v1/create swept every expired reservation with a scan of the
// expired list per stored row, under runtime.mutex. The sweep is now hash-set membership over a bounded batch (256),
// one DELETE statement, and an expired reservation that has not been swept yet is dead to every reader.
//
// Spec: Matrix Client-Server API v1.19, "POST /_matrix/media/v1/create" (the server "should limit the number of
// concurrent pending media uploads") and "PUT /_matrix/media/v3/upload/{serverName}/{mediaId}" (404 M_NOT_FOUND when
// "The MXC ID has expired"). ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentPendingMediaUpload.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/MediaService.hpp"
#include "merovingian/http/Header.hpp"
#include "merovingian/media/LocalMediaRepository.hpp"
#include "merovingian/media/PendingMediaUpload.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto owner = "@alice:example.org";

[[nodiscard]] auto sweep_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto login_alice(hs::ClientServerRuntime& runtime) -> std::string
{
    REQUIRE(
        hs::handle_client_server_request(runtime, {"POST",
                                                   "/_matrix/client/v3/register",
                                                   {},
                                                   merovingian::tests::registration_json("alice", "CorrectHorse7!")})
            .response.status == 200U);
    auto const response = hs::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                  R"("password":"CorrectHorse7!","device_id":"ALICE_DEV"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Adds `count` reservations that expired long ago, to the repository and to the store that mirrors it.
auto seed_expired(hs::ClientServerRuntime& runtime, std::size_t count, std::string const& prefix = "expiredseed")
    -> void
{
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        auto const media_id = prefix + std::to_string(index);
        runtime.homeserver.media_repository.pending_uploads.insert_or_assign(
            media_id, merovingian::media::PendingMediaUpload{media_id, owner, 1U, 2U});
        runtime.homeserver.database.persistent_store.pending_media_uploads.push_back({media_id, owner, 1U, 2U});
    }
}

[[nodiscard]] auto rows_examined(hs::ClientServerRuntime& runtime) -> std::uint64_t
{
    return runtime.homeserver.media_repository.pending_rows_examined.value() +
           runtime.homeserver.database.persistent_store.pending_media_rows_examined.value();
}

[[nodiscard]] auto expired_rows_held(hs::ClientServerRuntime& runtime) -> std::size_t
{
    auto const now = merovingian::media::remote_media_cache_now_ms();
    auto const& map = runtime.homeserver.media_repository.pending_uploads;
    return static_cast<std::size_t>(std::ranges::count_if(map, [now](auto const& entry) {
        return entry.second.expires_at_ms <= now;
    }));
}

[[nodiscard]] auto create(hs::ClientServerRuntime& runtime, std::string const& token) -> hs::OperationResult
{
    return hs::create_pending_media_upload(runtime.homeserver, token);
}

[[nodiscard]] auto create_over_http(hs::ClientServerRuntime& runtime, std::string const& token) -> std::uint16_t
{
    return static_cast<std::uint16_t>(
        hs::handle_client_server_request(runtime, {"POST", "/_matrix/media/v1/create", token, {}}).response.status);
}

} // namespace

SCENARIO("One create sweeps a bounded batch of expired reservations", "[media][async-upload][f16]")
{
    GIVEN("a server holding 1000 expired reservations")
    {
        auto started = hs::start_client_server(sweep_config());
        REQUIRE(started.started);
        auto const token = login_alice(started.runtime);
        started.runtime.homeserver.media_repository.config.max_pending_uploads_per_user = 1000U;
        seed_expired(started.runtime, 1000U);
        // The two limits are one rule: the plan lists no more than the store will delete in one statement.
        REQUIRE(merovingian::media::max_expired_reservations_swept_per_create ==
                merovingian::database::max_pending_media_deleted_per_commit);

        WHEN("one create is made")
        {
            auto const plan = merovingian::media::plan_pending_media_upload(
                started.runtime.homeserver.media_repository, owner, merovingian::media::remote_media_cache_now_ms());
            auto const created = create(started.runtime, token);

            THEN("the plan lists 256 expired reservations and the create removes only that many")
            {
                // Spec SHOULD: the server limits pending uploads; one create must not do unbounded work to do so.
                REQUIRE(plan.ok);
                REQUIRE(plan.expired_media_ids.size() == 256U);
                REQUIRE(created.ok);
                REQUIRE(started.runtime.homeserver.media_repository.pending_uploads.size() == 1000U - 256U + 1U);
                REQUIRE(started.runtime.homeserver.database.persistent_store.pending_media_uploads.size() ==
                        1000U - 256U + 1U);
            }
        }
    }
}

SCENARIO("Repeated creates clear a large backlog of expired reservations", "[media][async-upload][f16]")
{
    GIVEN("a server holding 2000 expired reservations and a user allowed many live ones")
    {
        auto started = hs::start_client_server(sweep_config());
        REQUIRE(started.started);
        auto const token = login_alice(started.runtime);
        started.runtime.homeserver.media_repository.config.max_pending_uploads_per_user = 1000U;
        seed_expired(started.runtime, 2000U);

        WHEN("the user creates eight times")
        {
            for (auto attempt = 0; attempt < 8; ++attempt)
            {
                REQUIRE(create(started.runtime, token).ok);
            }

            THEN("the backlog is gone from the repository and the store, and the live reservations remain")
            {
                // 8 * 256 = 2048 >= 2000: every expired reservation has been swept.
                REQUIRE(expired_rows_held(started.runtime) == 0U);
                REQUIRE(started.runtime.homeserver.media_repository.pending_uploads.size() == 8U);
                REQUIRE(started.runtime.homeserver.database.persistent_store.pending_media_uploads.size() == 8U);
            }
        }
    }
}

SCENARIO("The rows one create examines grow linearly with the expired backlog", "[media][async-upload][f16]")
{
    GIVEN("two servers, one holding 2000 expired reservations and one holding 4000")
    {
        auto small = hs::start_client_server(sweep_config());
        auto large = hs::start_client_server(sweep_config());
        REQUIRE(small.started);
        REQUIRE(large.started);
        auto const small_token = login_alice(small.runtime);
        auto const large_token = login_alice(large.runtime);
        seed_expired(small.runtime, 2000U);
        seed_expired(large.runtime, 4000U);

        WHEN("each makes one create")
        {
            auto const small_before = rows_examined(small.runtime);
            REQUIRE(create(small.runtime, small_token).ok);
            auto const small_cost = rows_examined(small.runtime) - small_before;
            auto const large_before = rows_examined(large.runtime);
            REQUIRE(create(large.runtime, large_token).ok);
            auto const large_cost = rows_examined(large.runtime) - large_before;

            THEN("doubling the backlog doubles the rows examined, no more")
            {
                // Work under runtime.mutex: a pass over the reservations held, not one pass per reservation.
                REQUIRE(small_cost >= 2000U);
                REQUIRE(large_cost <= 2U * small_cost + 16U);
            }
        }
    }
}

SCENARIO("An expired reservation that has not been swept yet counts toward no quota", "[media][async-upload][f16]")
{
    GIVEN("alice, with a limit of two live reservations and 600 expired ones of her own")
    {
        auto started = hs::start_client_server(sweep_config());
        REQUIRE(started.started);
        auto const token = login_alice(started.runtime);
        started.runtime.homeserver.media_repository.config.max_pending_uploads_per_user = 2U;
        started.runtime.homeserver.media_repository.config.max_pending_uploads = 3U;
        seed_expired(started.runtime, 600U);

        WHEN("she creates twice, leaving expired reservations unswept, and a third time")
        {
            auto const first = create_over_http(started.runtime, token);
            auto const second = create_over_http(started.runtime, token);
            auto const unswept = expired_rows_held(started.runtime);
            auto const third = create_over_http(started.runtime, token);

            THEN("the first two succeed because the backlog is not counted, and the third meets the live limit")
            {
                // Spec SHOULD: limit concurrent pending uploads; an expired reservation is not pending.
                REQUIRE(first == 200U);
                REQUIRE(second == 200U);
                REQUIRE(unswept == 600U - 512U);
                REQUIRE(third == 429U);
            }
        }
    }
}

SCENARIO("An expired reservation that has not been swept yet cannot be uploaded to", "[media][async-upload][f16]")
{
    GIVEN("alice with 300 expired reservations of her own, one create having swept 256 of them")
    {
        auto started = hs::start_client_server(sweep_config());
        REQUIRE(started.started);
        auto const token = login_alice(started.runtime);
        seed_expired(started.runtime, 300U);
        REQUIRE(create(started.runtime, token).ok);
        auto const& pending = started.runtime.homeserver.media_repository.pending_uploads;
        auto const now = merovingian::media::remote_media_cache_now_ms();
        auto const leftover = std::ranges::find_if(pending, [now](auto const& entry) {
            return entry.second.expires_at_ms <= now;
        });
        REQUIRE(leftover != pending.end());
        auto const media_id = leftover->first;

        WHEN("she uploads to one of the expired reservations still held")
        {
            auto const response = hs::handle_client_server_request(
                started.runtime, {"PUT",
                                  "/_matrix/media/v3/upload/example.org/" + media_id,
                                  token,
                                  std::string{"\x89PNG\r\n\x1a\nsweep-image"},
                                  {merovingian::http::Header{"Content-Type", "image/png"}}});

            THEN("the answer is 404 M_NOT_FOUND, as for any expired reservation")
            {
                // Spec MUST: 404 M_NOT_FOUND when "The MXC ID has expired".
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_NOT_FOUND");
            }
        }
    }
}
