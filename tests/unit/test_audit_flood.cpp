// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// AUTH-1 (security-audit-report-2026-09-29.md): an unauthenticated client must
// not be able to grow the audit trail without bound or force one synchronous
// durable audit commit per request. These scenarios drive the real client-server
// dispatcher with hostile traffic and assert on the resulting audit state.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/AuditRateGate.hpp"
#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/bounded_text.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto flood_test_config() -> merovingian::config::Config
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

// Every durable audit row ever appended to the store: the retained window plus
// the rows the in-memory cap has already evicted. The database table holds one
// row (one synchronous commit) per append, so this is the commit count.
[[nodiscard]] auto durable_audit_rows(merovingian::database::PersistentStore const& store) -> std::size_t
{
    return store.audit_log.size() + static_cast<std::size_t>(store.audit_log_evicted);
}

} // namespace

SCENARIO("Audit events that are not per-request rejections are neither sampled nor lost",
         "[homeserver][audit][flood][auth-1]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(flood_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& database = runtime.homeserver.database;
        auto const rows_before = durable_audit_rows(database.persistent_store);

        WHEN("more login-success audit events than the in-memory cap are appended")
        {
            auto const total = merovingian::database::max_in_memory_audit_events + 300U;
            for (auto i = std::size_t{0U}; i < total; ++i)
            {
                merovingian::homeserver::append_local_audit(database, merovingian::observability::AuditCategory::auth,
                                                            "auth.login", "@alice:example.org", std::to_string(i),
                                                            "ok");
            }

            THEN("every event reached the durable store while both in-memory windows stayed at the cap")
            {
                REQUIRE(durable_audit_rows(database.persistent_store) - rows_before == total);
                REQUIRE(database.audit_events.size() == merovingian::database::max_in_memory_audit_events);
                REQUIRE(database.persistent_store.audit_log.size() ==
                        merovingian::database::max_in_memory_audit_events);
                REQUIRE(database.audit_events.back().target == std::to_string(total - 1U));
                REQUIRE(database.persistent_store.audit_log.back().target == std::to_string(total - 1U));
            }
        }
    }
}
