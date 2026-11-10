// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
//
// +-------------------------------------------------------------------------+
// |  SECURITY AUDIT AUTH-4                                                  |
// |  Medium-severity authentication finding from 2026-09-29 audit.          |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                  |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md               |
// +-------------------------------------------------------------------------+
//
// AUTH-4: Argon2id password and registration-token verification must not
// be allowed to consume unbounded CPU under the global runtime mutex. A
// bounded admission semaphore limits in-flight hash work; when saturated,
// the server sheds load with HTTP 429 / M_LIMIT_EXCEEDED before any work is
// performed.

#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <memory>
#include <string>

SCENARIO("Argon2idAdmission bounds concurrent hash work", "[auth][security][audit][auth4]")
{
    GIVEN("an admission semaphore with capacity two")
    {
        auto admission = merovingian::auth::Argon2idAdmission{2U};

        WHEN("two slots are acquired")
        {
            auto first = admission.try_acquire();
            auto second = admission.try_acquire();

            THEN("both slots are held")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
            }

            AND_WHEN("a third slot is requested")
            {
                auto third = admission.try_acquire();

                THEN("it is refused while the first two are held")
                {
                    REQUIRE_FALSE(third.has_value());
                }
            }

            AND_WHEN("one slot is released")
            {
                first.reset();
                auto third = admission.try_acquire();

                THEN("a waiting unit of work can take its place")
                {
                    REQUIRE(third.has_value());
                }
            }
        }
    }
}
