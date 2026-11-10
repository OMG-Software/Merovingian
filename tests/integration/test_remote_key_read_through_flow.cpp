// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A6 (Complement run 9): a federation worker's key mirror is a snapshot taken
// when it started. A server main met afterwards was unknown to the worker, which
// then fetched its keys again over a fresh connection, discovery and TLS
// handshake included, in front of the first PDU main had already authenticated.
// The worker may read the row main verified and persisted; it still never reads
// this server's own signing secret.
//
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys
// (valid_until_ts: "Servers MUST use the lesser of this field and 7 days").
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/federation/KeyMirrorRefresh.hpp"
#include "merovingian/federation/ServerDiscoveryResult.hpp"
#include "merovingian/federation/RemoteKeyCache.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartOptions.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/http/OutboundClient.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <system_error>

namespace
{
[[nodiscard]] auto runtime_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            security,
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}
} // namespace

SCENARIO("Only a federation worker's runtime reads signing keys through to the database",
         "[federation][remote-key-cache][worker-key-cache][worker-key-read-through]")
{
    GIVEN("a runtime started as main and another started with the federation worker load profile")
    {
        REQUIRE(sodium_init() >= 0);
        auto const main = merovingian::homeserver::start_runtime(merovingian::homeserver::RuntimeStartOptions{
            .config = runtime_config(),
        });
        auto const worker = merovingian::homeserver::start_runtime(merovingian::homeserver::RuntimeStartOptions{
            .config = runtime_config(),
            .signing_disabled = true,
            .database_load_profile = merovingian::database::TableLoadProfile::federation_worker,
        });

        WHEN("each runtime's database state is inspected")
        {
            THEN("main's mirror stays authoritative and the worker's re-reads on a miss")
            {
                REQUIRE(main.started);
                REQUIRE(worker.started);
                REQUIRE_FALSE(main.runtime.database.remote_signing_keys_read_through);
                REQUIRE(worker.runtime.database.remote_signing_keys_read_through);
            }
        }
    }
}
