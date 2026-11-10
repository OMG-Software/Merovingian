// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// F-16 (security audit run 4): POST /_matrix/media/v1/create swept every expired reservation with a scan of the
// expired list per stored row, under runtime.mutex. The sweep is now hash-set membership over a bounded batch (256),
// one DELETE statement, and an expired reservation that has not been swept yet is dead to every reader.
//
// Spec: Matrix Client-Server API v1.19, "POST /_matrix/media/v1/create" (the server "should limit the number of
// concurrent pending media uploads") and "PUT /_matrix/media/v3/upload/{serverName}/{mediaId}" (404 M_NOT_FOUND when
// "The MXC ID has expired"). ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
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
#include "merovingian/homeserver/media_service.hpp"
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

constexpr auto owner = "@alice:example.org";

} // namespace

SCENARIO("The sweep is one DELETE on a SQLite store", "[media][async-upload][f16][database]")
{
    GIVEN("a SQLite store holding three expired reservations and one live one")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-f16-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        std::filesystem::remove(path);
        auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto index = 0; index < 3; ++index)
        {
            REQUIRE(merovingian::database::commit_pending_media_upload(
                store, {"old" + std::to_string(index), owner, 1U, 2U}, {}));
        }
        REQUIRE(merovingian::database::commit_pending_media_upload(store, {"live", owner, 1U, 9999999999999U}, {}));

        WHEN("a create commits with the three expired reservations listed")
        {
            auto const committed = merovingian::database::commit_pending_media_upload(
                store, {"fresh", owner, 10U, 9999999999999U}, {"old0", "old1", "old2"});

            THEN("the rows are gone from memory and from the file, and the live ones remain")
            {
                REQUIRE(committed);
                REQUIRE(store.pending_media_uploads.size() == 2U);
                auto reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                REQUIRE(reopened.ok);
                auto ids = std::vector<std::string>{};
                for (auto const& row : reopened.store.pending_media_uploads)
                {
                    ids.push_back(row.media_id);
                }
                std::ranges::sort(ids);
                REQUIRE(ids == std::vector<std::string>{"fresh", "live"});
            }
        }

        WHEN("a commit lists more expired reservations than one statement may delete")
        {
            auto too_many = std::vector<std::string>{};
            for (auto index = std::size_t{0U}; index <= merovingian::database::max_pending_media_deleted_per_commit;
                 ++index)
            {
                too_many.push_back("absent" + std::to_string(index));
            }

            THEN("it is refused and nothing changes")
            {
                REQUIRE_FALSE(merovingian::database::commit_pending_media_upload(
                    store, {"fresh", owner, 10U, 9999999999999U}, too_many));
                REQUIRE(store.pending_media_uploads.size() == 4U);
            }
        }

        std::filesystem::remove(path);
    }
}
