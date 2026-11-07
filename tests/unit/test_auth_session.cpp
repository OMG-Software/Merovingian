// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/RegistrationPolicy.hpp"
#include "merovingian/auth/session.hpp"
#include "merovingian/homeserver/LocalDatabaseScope.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("Registration policy remains disabled by default and token-gated when enabled", "[auth][client-api]")
{
    GIVEN("default, missing-token, and token-present registration policies")
    {
        auto const default_policy = merovingian::auth::RegistrationPolicy{};
        auto const missing_token_policy = merovingian::auth::RegistrationPolicy{true, true, false};
        auto const token_present_policy = merovingian::auth::RegistrationPolicy{true, true, true};

        // Tests that ran before us on this thread may have left the
        // audit-sink thread_local pointing at a `LocalDatabase` that is now
        // out of scope. The auth test never exercises the audit log, so
        // clear this thread's pointer — `local_audit_sink` early-returns on
        // a null database. This resets only the thread_local database
        // pointer (homeserver/local_services.cpp), NOT the process-wide
        // `observability::the_audit_sink()` function pointer: that one is a
        // global singleton shared by every test in the binary, permanently
        // downgraded to `default_audit_sink` for the rest of the process by
        // an earlier version of this reset — which silently broke any
        // *later* test asserting on actual audit-log contents (e.g.
        // test_local_database_scope.cpp's worker-thread audit test), since
        // the sink is armed to `local_audit_sink` at most once per process
        // (see `ensure_audit_sink_installed()`'s magic static) and nothing
        // ever re-arms it after a raw `set_audit_sink` reset. With
        // `HomeserverRuntime` owning the audit-sink install via its
        // `audit_sink_scope` member, the install is normally cleared on
        // runtime destruction; this call is a belt-and-braces defence for
        // the rare test that constructs a `LocalDatabase` by some other path
        // (e.g. a direct call to `bootstrap_local_database`).
        merovingian::homeserver::set_current_audit_database(nullptr);

        WHEN("registration policy is evaluated")
        {
            auto const disabled = merovingian::auth::registration_policy(default_policy);
            auto const missing_token = merovingian::auth::registration_policy(missing_token_policy);
            auto const token_present = merovingian::auth::registration_policy(token_present_policy);

            THEN("registration fails closed until enabled with the required token")
            {
                REQUIRE_FALSE(disabled.allowed);
                REQUIRE(disabled.reason == "registration disabled");
                REQUIRE_FALSE(missing_token.allowed);
                REQUIRE(missing_token.reason == "registration token required");
                REQUIRE(token_present.allowed);
            }
        }
    }
}
