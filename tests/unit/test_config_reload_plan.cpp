// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/reload_plan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

SCENARIO("Reload plan is empty for identical configs", "[config][reload]")
{
    GIVEN("identical current and next configs")
    {
        auto const current = merovingian::config::Config{};
        auto const next = merovingian::config::Config{};

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the plan reports no changes")
            {
                REQUIRE_FALSE(plan.has_changes());
                REQUIRE_FALSE(plan.has_restart_required_changes());
                REQUIRE(plan.reloadable_change_count() == 0U);
                REQUIRE(plan.restart_required_change_count() == 0U);
                REQUIRE(plan.changes().empty());
                REQUIRE(merovingian::config::reload_plan_summary(plan) ==
                        "Reload plan: changes=0 reloadable=0 restart_required=0");
            }
        }
    }
}

SCENARIO("Reload plan marks runtime policy changes as reloadable", "[config][reload]")
{
    GIVEN("current and next configs with runtime policy changes")
    {
        auto current_security = merovingian::config::SecurityConfig{};
        auto next_security = merovingian::config::SecurityConfig{};
        next_security.federation.remote_timeout = "45s";
        next_security.federation.max_transaction_size = "8MiB";
        next_security.federation.allowed_servers = std::vector<std::string>{"matrix.org", "example.net"};
        next_security.federation.denied_servers = std::vector<std::string>{"bad.example"};

        auto const current = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         current_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
        auto const next = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         next_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the changes are reloadable")
            {
                REQUIRE(plan.has_changes());
                REQUIRE_FALSE(plan.has_restart_required_changes());
                REQUIRE(plan.changes().size() == 4U);
                REQUIRE(plan.reloadable_change_count() == 4U);
                REQUIRE(plan.restart_required_change_count() == 0U);
                REQUIRE(plan.changes()[0].key == "security.federation.allowed_servers");
                REQUIRE(plan.changes()[1].key == "security.federation.denied_servers");
                REQUIRE(plan.changes()[2].key == "security.federation.max_transaction_size");
                REQUIRE(plan.changes()[3].key == "security.federation.remote_timeout");
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(plan.changes()[1].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(plan.changes()[2].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(plan.changes()[3].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(merovingian::config::reload_plan_summary(plan) ==
                        "Reload plan: changes=4 reloadable=4 restart_required=0");
            }
        }
    }
}

SCENARIO("Reload plan marks media acceptance policy changes as reloadable", "[config][reload][media]")
{
    GIVEN("current and next configs differing only in the media acceptance policy keys")
    {
        auto current_security = merovingian::config::SecurityConfig{};
        auto next_security = merovingian::config::SecurityConfig{};
        next_security.media.local_upload_policy = "allow";
        next_security.media.remote_fetch_media_policy = "deny";

        auto const current = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         current_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
        auto const next = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         next_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("both keys are reported as reloadable, not restart-required")
            {
                REQUIRE(plan.has_changes());
                REQUIRE_FALSE(plan.has_restart_required_changes());
                REQUIRE(plan.changes().size() == 2U);
                REQUIRE(std::ranges::all_of(plan.changes(), [](auto const& change) {
                    return change.policy == merovingian::config::ReloadPolicy::reloadable;
                }));
                REQUIRE(std::ranges::any_of(plan.changes(), [](auto const& change) {
                    return change.key == "security.media.local_upload_policy";
                }));
                REQUIRE(std::ranges::any_of(plan.changes(), [](auto const& change) {
                    return change.key == "security.media.remote_fetch_media_policy";
                }));
            }
        }
    }
}

SCENARIO("Reload plan flags restart-required identity and secret source changes", "[config][reload]")
{
    GIVEN("current and next configs with identity and secret source changes")
    {
        auto current_server = merovingian::config::ServerConfig{};
        auto next_server = merovingian::config::ServerConfig{};
        auto current_database = merovingian::config::DatabaseConfig{};
        auto next_database = merovingian::config::DatabaseConfig{};
        next_server.server_name = "new.example.org";
        next_database.uri_file = "/run/secrets/new-db-uri";

        auto const current = merovingian::config::Config{
            current_server,
            merovingian::config::ListenersConfig{},
            current_database,
            merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{},
        };
        auto const next = merovingian::config::Config{
            next_server,
            merovingian::config::ListenersConfig{},
            next_database,
            merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{},
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the changes require restart")
            {
                REQUIRE(plan.has_changes());
                REQUIRE(plan.has_restart_required_changes());
                REQUIRE(plan.changes().size() == 2U);
                REQUIRE(plan.reloadable_change_count() == 0U);
                REQUIRE(plan.restart_required_change_count() == 2U);
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(plan.changes()[1].policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_plan_summary(plan) ==
                        "Reload plan: changes=2 reloadable=0 restart_required=2");
            }
        }
    }
}

namespace
{

[[nodiscard]] auto plan_has_key(merovingian::config::ReloadPlan const& plan, std::string const& key) -> bool
{
    return std::ranges::any_of(plan.changes(), [&](merovingian::config::ReloadChange const& change) {
        return change.key == key;
    });
}

} // namespace

// Regression for #421: build_reload_plan produced no diff at all for these
// blocks, so `--plan-config-reload` reported "no changes" and the edit was
// silently dropped.
SCENARIO("Reload plan emits a diff for every documented config block", "[config][reload]")
{
    GIVEN("a next config that changes cors, turn, secrets, trust_safety, token lifetimes, worker, "
          "rate limits and log modules")
    {
        auto const current = merovingian::config::Config{};

        auto server = merovingian::config::ServerConfig{};
        server.cors.max_age = 60U;
        server.turn.server = "turn:turn.example.org:3478";

        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = "/etc/merovingian/master.key";
        security.trust_safety.enabled = true;
        security.access_token_lifetime_ms = 3600000LL / 24LL;
        security.refresh_token_lifetime_ms = 1234LL;

        auto rate_limits = merovingian::config::ClientRateLimitsConfig{};
        rate_limits.default_per_ip = {30U, 60U};
        rate_limits.per_ip["/login"] = {10U, 60U};
        rate_limits.tier["auth_sensitive"] = {10U, 60U};

        // The per-origin non-/send request cap is part of the federation
        // security block; a change must surface in the plan.
        security.federation.per_origin_request_rate = {300U, 60U};

        auto log_modules = merovingian::config::LogModulesConfig{};
        log_modules.levels["federation"] = merovingian::observability::LogLevel::debug;

        auto worker = merovingian::config::FederationWorkerConfig{};
        worker.shards = 4U;

        auto const next = merovingian::config::Config{
            server,
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
            rate_limits,
            log_modules,
            worker,
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("every edited key appears in the plan")
            {
                REQUIRE(plan.has_changes());
                REQUIRE(plan_has_key(plan, "server.cors.max_age"));
                REQUIRE(plan_has_key(plan, "server.turn.server"));
                REQUIRE(plan_has_key(plan, "security.secrets.master_key_file"));
                REQUIRE(plan_has_key(plan, "security.trust_safety.enabled"));
                REQUIRE(plan_has_key(plan, "security.access_token_lifetime_ms"));
                REQUIRE(plan_has_key(plan, "security.refresh_token_lifetime_ms"));
                REQUIRE(plan_has_key(plan, "federation.worker.shards"));
                REQUIRE(plan_has_key(plan, "client_rate_limits.default_per_ip"));
                REQUIRE(plan_has_key(plan, "client_rate_limits.per_ip./login"));
                REQUIRE(plan_has_key(plan, "client_rate_limits.tier.auth_sensitive"));
                REQUIRE(plan_has_key(plan, "security.federation.per_origin_request_rate"));
                REQUIRE(plan_has_key(plan, "log_modules.federation"));
            }

            THEN("startup-only blocks are flagged restart_required, runtime blocks reloadable")
            {
                for (auto const& change : plan.changes())
                {
                    if (change.key == "security.secrets.master_key_file" ||
                        change.key.starts_with("federation.worker.") || change.key.starts_with("server.cors.") ||
                        change.key.starts_with("client_rate_limits.") || change.key.starts_with("log_modules."))
                    {
                        REQUIRE(change.policy == merovingian::config::ReloadPolicy::restart_required);
                    }
                    else
                    {
                        REQUIRE(change.policy == merovingian::config::ReloadPolicy::reloadable);
                    }
                }
            }
        }
    }
}
