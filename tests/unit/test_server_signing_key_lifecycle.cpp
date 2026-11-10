// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         SERVER SIGNING KEY LIFECYCLE TESTS                              |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys |
// |                                                                         |
// |  A homeserver's Ed25519 signing key is its federation identity. It may  |
// |  only change through an explicit rotation. `valid_until_ts` says when   |
// |  peers should REFRESH the published key list - it is not a lifetime     |
// |  after which the server silently adopts a new identity.                 |
// |                                                                         |
// |  Every REQUIRE here encodes that invariant. Fix the implementation, do  |
// |  not weaken the assertions.                                             |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/Ed25519Keypair.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/crypto/RuntimeMultiKeyEd25519Provider.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartOptions.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

// Merovingian invariant (cache freshness):
// GET /_matrix/key/v2/server is served from a lock-free cache. A cached document is
// only servable while it is fresh; once its refresh deadline passes it must be
// re-published, otherwise long-running servers keep serving a document whose
// valid_until_ts has already gone into the past.
SCENARIO("The key server cache stops serving a document past its refresh deadline",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a cache holding a document with a refresh deadline")
    {
        auto cache = merovingian::homeserver::KeyServerCache{};
        cache.store("{\"published\":true}", 1'000U);

        WHEN("the cache is read before and after the deadline")
        {
            auto const fresh = cache.load(999U);
            auto const stale = cache.load(1'001U);

            THEN("only the fresh read returns the document")
            {
                REQUIRE(fresh.has_value());
                REQUIRE(*fresh == "{\"published\":true}");
                REQUIRE(!stale.has_value());
            }
        }
    }
}
