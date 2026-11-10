// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/HttpConnectionDispatcher.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>

namespace
{

class TestSqliteConnection final
{
public:
    explicit TestSqliteConnection(std::filesystem::path const& path)
    {
        std::ignore = sqlite3_open(path.string().c_str(), &connection_);
    }

    TestSqliteConnection(TestSqliteConnection const& other) = delete;
    auto operator=(TestSqliteConnection const& other) -> TestSqliteConnection& = delete;
    TestSqliteConnection(TestSqliteConnection&& other) noexcept = delete;
    auto operator=(TestSqliteConnection&& other) noexcept -> TestSqliteConnection& = delete;

    ~TestSqliteConnection()
    {
        sqlite3_close(connection_);
    }

    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        auto* error = static_cast<char*>(nullptr);
        auto const ok = sqlite3_exec(connection_, sql.c_str(), nullptr, nullptr, &error) == SQLITE_OK;
        sqlite3_free(error);
        return ok;
    }

private:
    sqlite3* connection_{nullptr};
};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
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

[[nodiscard]] auto unique_sqlite_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-review-" + suffix + "-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto remote_runtime(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 4102444800000U,
                          merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto x_matrix_authorization(std::string_view origin, std::string_view key_id, std::string_view key_seed,
                                          std::string_view destination, std::string_view method,
                                          std::string_view target, std::string_view body) -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return std::string{"X-Matrix origin=\""} + std::string{origin} + "\",key=\"" + std::string{key_id} + "\",sig=\"" +
           signature + "\",destination=\"" + std::string{destination} + "\"";
}

} // namespace

SCENARIO("Admin routes split missing-token 401 from non-admin 403", "[homeserver][security][review]")
{
    GIVEN("a runtime with an admin user and a regular user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin_user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        auto const admin_login =
            merovingian::homeserver::login_local_user(runtime, admin_user.value, "CorrectHorse7!", "ADMIN1");
        auto const normal_user = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse8!",
                                                                              merovingian::tests::registration_token);
        auto const normal_login =
            merovingian::homeserver::login_local_user(runtime, normal_user.value, "CorrectHorse8!", "USER1");
        REQUIRE(admin_login.ok);
        REQUIRE(normal_login.ok);

        WHEN("admin, non-admin, and missing-token callers hit the admin health route")
        {
            auto const admin_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", admin_login.value, {}});
            auto const normal_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", normal_login.value, {}});
            auto const missing_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}});

            THEN("admin gets 200, non-admin gets 403, missing token gets 401")
            {
                REQUIRE(admin_response.status == 200U);
                REQUIRE(normal_response.status == 403U);
                REQUIRE(normal_response.body == "admin privileges required");
                REQUIRE(missing_response.status == 401U);
                REQUIRE(missing_response.body == "admin authentication required");
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_admin_user(runtime, normal_login.value).has_value());
            }
        }

        WHEN("non-admin and missing-token callers hit the admin media moderation routes")
        {
            // The auth gate fires before any media lookup, so a non-existent
            // media id still surfaces the 401/403 distinction rather than 404.
            auto constexpr media_id = std::string_view{"media-not-present"};
            auto const quarantine_non_admin = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/quarantine/" + std::string{media_id}, normal_login.value,
                          "policy review"});
            auto const quarantine_missing = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_merovingian/admin/media/quarantine/" + std::string{media_id}, {}, "policy review"});
            auto const release_non_admin = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_merovingian/admin/media/release/" + std::string{media_id}, normal_login.value, {}});
            auto const release_missing = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/release/" + std::string{media_id}, {}, {}});
            auto const remove_non_admin = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/remove/" + std::string{media_id}, normal_login.value,
                          "operator removal"});
            auto const remove_missing = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_merovingian/admin/media/remove/" + std::string{media_id}, {}, "operator removal"});

            THEN("non-admin gets 403 and missing token gets 401 on every moderation route")
            {
                REQUIRE(quarantine_non_admin.status == 403U);
                REQUIRE(quarantine_non_admin.body == "admin privileges required");
                REQUIRE(quarantine_missing.status == 401U);
                REQUIRE(quarantine_missing.body == "admin authentication required");
                REQUIRE(release_non_admin.status == 403U);
                REQUIRE(release_missing.status == 401U);
                REQUIRE(remove_non_admin.status == 403U);
                REQUIRE(remove_missing.status == 401U);
            }
        }
    }
}

SCENARIO("Runtime membership projection ignores non-joined invite and knock updates",
         "[homeserver][review][membership]")
{
    GIVEN("a local room whose joined-members projection already contains the same user")
    {
        auto database = merovingian::homeserver::LocalDatabase{};
        database.rooms.push_back({"!room:example.org", "@alice:example.org", {"@bob:example.org"}, {}});

        WHEN("invite and knock membership updates are applied to the runtime projection")
        {
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "invite");
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "knock");

            THEN("the joined-members projection is unchanged")
            {
                REQUIRE(database.rooms.size() == 1U);
                REQUIRE(database.rooms.front().members.size() == 1U);
                REQUIRE(database.rooms.front().members.front() == "@bob:example.org");
            }
        }
    }
}

SCENARIO("Federation dispatch exposes only federation routes", "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime served through federation dispatch mode")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        WHEN("admin, client, and federation key routes are requested")
        {
            auto const admin = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const client_register = merovingian::homeserver::dispatch_local_http_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_pipe("alice", "CorrectHorse7!")},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const keys = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("non-federation surfaces are hidden and federation keys remain reachable")
            {
                REQUIRE(admin.status == 404U);
                REQUIRE(client_register.status == 404U);
                REQUIRE(keys.status == 200U);
                REQUIRE(keys.body.find("\"verify_keys\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation auth failures do not surface as client-style 401s", "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime handling a federation request without valid auth")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the inbound federation profile route is requested without an X-Matrix signature")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime, {"GET",
                          "/_matrix/federation/v1/query/profile?user_id=%40jcadmin%3Apong.ping.me.uk&field=displayname",
                          {},
                          {}});

            THEN("the failure is reported as a server-side federation error instead of 401")
            {
                // Synapse can propagate 401 from a federation exchange back to a
                // client-server request, which Element interprets as an invalid
                // access token and turns into an automatic logout.
                REQUIRE(response.status == 502U);
                REQUIRE(response.body.find("malformed federation authorization") != std::string::npos);
                REQUIRE(response.body.find("\"errcode\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Pipe-delimited federation fixture auth is rejected on the production federation listener",
         "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime handling a federation request with legacy pipe-delimited auth")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the inbound federation route is requested with the fixture token format")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime, {"GET",
                          "/_matrix/federation/v1/query/profile?user_id=%40jcadmin%3Aexample.org&field=displayname",
                          "remote.example.org|ed25519:auto|signature|example.org|1000|canonical",
                          {}});

            THEN("the request is rejected instead of being accepted as real X-Matrix auth")
            {
                REQUIRE(response.status == 502U);
                REQUIRE(response.body.find("malformed federation authorization") != std::string::npos);
                REQUIRE(response.body.find("\"errcode\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Inbound receipt EDUs read event_ids arrays instead of ad hoc event_id fields",
         "[homeserver][federation][edu][receipt][review][regression]")
{
    GIVEN("a started client-server runtime with a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto constexpr remote_origin = "remote.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "receipt-review-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));

        // Receipt EDUs are only stored for rooms this server is in (0.12.5
        // audit, finding 13), and the receipt subject must be a joined member
        // of the room (FED-8), so seed both a local member and the remote
        // receipt subject before testing event_ids shape behaviour.
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!room:example.org", "@local:example.org", "join", 1U});
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!room:example.org", "@alice:remote.example.org", "join", 2U});

        auto const content =
            R"({"!room:example.org":{"m.read":{"@alice:remote.example.org":{"event_ids":["$event:remote.example.org"],"data":{"ts":42}}}}})";
        auto const transaction =
            merovingian::federation::build_edu_transaction_body(remote_origin, "m.receipt", content);
        REQUIRE(transaction.has_value());
        auto const target = std::string{"/_matrix/federation/v1/send/txn-receipt-1"};

        WHEN("the receipt EDU is delivered through the local federation listener")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver, {"PUT", target,
                                     x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed,
                                                            "example.org", "PUT", target, *transaction),
                                     *transaction});

            THEN("the stored receipt uses the first event_ids entry as required by the Matrix shape")
            {
                REQUIRE(response.status == 200U);
                auto const receipt = std::ranges::find_if(runtime.homeserver.database.persistent_store.receipts,
                                                          [](auto const& candidate) {
                                                              return candidate.user_id == "@alice:remote.example.org";
                                                          });
                REQUIRE(receipt != runtime.homeserver.database.persistent_store.receipts.end());
                REQUIRE(receipt->event_id == "$event:remote.example.org");
                REQUIRE(receipt->receipt_type == "m.read");
            }
        }
    }
}

// Spec (S-S API, m.receipt): "only a single <receipt_type> should be used: m.read.
// m.read.private MUST NOT appear in this federated m.receipt EDU." A peer that sends other
// receipt types anyway must not get them stored, because the client-server surface would
// otherwise have to be trusted to withhold them (CSAZ-4).
SCENARIO("Inbound receipt EDUs keep only m.read receipts", "[homeserver][federation][edu][receipt][security][csaz-4]")
{
    GIVEN("a started client-server runtime with a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto constexpr remote_origin = "remote.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "receipt-types-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!room:example.org", "@local:example.org", "join", 1U});
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!room:example.org", "@alice:remote.example.org", "join", 2U});

        auto const content =
            R"({"!room:example.org":{)"
            R"("m.read":{"@alice:remote.example.org":{"event_ids":["$e:remote.example.org"],"data":{"ts":42}}},)"
            R"("m.read.private":{"@alice:remote.example.org":{"event_ids":["$e:remote.example.org"],"data":{"ts":43}}},)"
            R"("m.fully_read":{"@alice:remote.example.org":{"event_ids":["$e:remote.example.org"],"data":{"ts":44}}}}})";
        auto const transaction =
            merovingian::federation::build_edu_transaction_body(remote_origin, "m.receipt", content);
        REQUIRE(transaction.has_value());
        auto const target = std::string{"/_matrix/federation/v1/send/txn-receipt-types-1"};

        WHEN("the EDU carrying m.read, m.read.private and m.fully_read is delivered")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver, {"PUT", target,
                                     x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed,
                                                            "example.org", "PUT", target, *transaction),
                                     *transaction});

            THEN("only the m.read receipt is stored")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.receipts.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.receipts.front().receipt_type == "m.read");
            }
        }
    }
}

SCENARIO("Inbound presence EDUs persist non-negative last_active_ago values from the sending origin",
         "[homeserver][federation][edu][presence][review][regression]")
{
    GIVEN("a started client-server runtime and a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto constexpr remote_origin = "remote.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "presence-last-active-review-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));
        // Presence is kept only for a remote user who shares a joined room with a local user.
        auto& memberships = runtime.homeserver.database.persistent_store.memberships;
        memberships.push_back({"!shared:example.org", "@local:example.org", "join", 1U});
        memberships.push_back({"!shared:example.org", "@alice:remote.example.org", "join", 2U});

        auto const presence_content = R"({
            "push":[
                {
                    "user_id":"@alice:remote.example.org",
                    "presence":"online",
                    "status_msg":"available",
                    "last_active_ago":42000,
                    "currently_active":true
                }
            ]
        })";
        auto const presence_transaction =
            merovingian::federation::build_edu_transaction_body(remote_origin, "m.presence", presence_content);
        REQUIRE(presence_transaction.has_value());
        auto const target = std::string{"/_matrix/federation/v1/send/txn-presence-accepted-1"};

        WHEN("the remote sends a valid presence EDU with a non-negative last_active_ago")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver, {"PUT", target,
                                     x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed,
                                                            "example.org", "PUT", target, *presence_transaction),
                                     *presence_transaction});

            THEN("the presence snapshot is stored with the provided activity age")
            {
                REQUIRE(response.status == 200U);
                auto const persisted =
                    std::ranges::find_if(runtime.homeserver.database.persistent_store.presence_states,
                                         [](merovingian::database::PersistentPresence const& state) {
                                             return state.user_id == "@alice:remote.example.org";
                                         });
                REQUIRE(persisted != runtime.homeserver.database.persistent_store.presence_states.end());
                REQUIRE(persisted->presence == "online");
                REQUIRE(persisted->status_msg == "available");
                REQUIRE(persisted->last_active_ago == 42000);
                REQUIRE(persisted->currently_active);
            }
        }
    }
}

SCENARIO("Migration planning rejects unsupported future versions without iterating", "[database][migration][review]")
{
    GIVEN("a far future schema version")
    {
        auto const future_version = merovingian::database::current_schema_version() + 1000000U;

        WHEN("a migration plan is requested")
        {
            auto const plan = merovingian::database::migration_plan_between(future_version, 0U);
            auto const validation = merovingian::database::migration_plan_is_valid(plan);

            THEN("the unsupported range is represented as an invalid bounded plan")
            {
                REQUIRE(plan.current_version == future_version);
                REQUIRE(plan.target_version == 0U);
                REQUIRE(plan.steps.empty());
                REQUIRE_FALSE(validation.valid);
                REQUIRE(validation.reason == "migration plan has no steps");
            }
        }
    }
}

SCENARIO("Migration application reapplies upgrade statements after downgrade", "[database][migration][review]")
{
    GIVEN("a schema upgraded, downgraded, and then upgraded again")
    {
        auto const upgraded = merovingian::database::apply_migration_plan(
            {}, merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));
        REQUIRE(upgraded.ok);
        auto const downgraded = merovingian::database::apply_migration_plan(
            upgraded.state,
            merovingian::database::migration_plan_between(merovingian::database::current_schema_version(), 0U));
        REQUIRE(downgraded.ok);

        WHEN("the schema is upgraded again")
        {
            auto const reapplied = merovingian::database::apply_migration_plan(
                downgraded.state,
                merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));

            THEN("tables are recreated even though migration history still contains the old upgrade record")
            {
                REQUIRE(reapplied.ok);
                REQUIRE(reapplied.state.version == merovingian::database::current_schema_version());
                REQUIRE(reapplied.state.tables.size() == merovingian::database::current_schema_tables().size());
            }
        }
    }
}

SCENARIO("Persistent store records insert statements only for accepted user and device rows",
         "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("duplicate users and devices are stored")
        {
            auto const first_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const duplicate_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:2", false, false, false});
            auto const first_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const duplicate_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Duplicate laptop"});

            THEN("rejected duplicates do not leave replay statements behind")
            {
                REQUIRE(first_user);
                REQUIRE_FALSE(duplicate_user);
                REQUIRE(first_device);
                REQUIRE_FALSE(duplicate_device);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.captured_statements.size() == 2U);
                REQUIRE(store.captured_statements[0].name == "insert_user");
                REQUIRE(store.captured_statements[1].name == "insert_device");
            }
        }
    }
}

SCENARIO("Persistent store rejects duplicate token hashes before recording inserts", "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("the same token hash is stored twice")
        {
            auto const first = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});
            auto const duplicate = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});

            THEN("only one token row and statement are recorded")
            {
                REQUIRE(first);
                REQUIRE_FALSE(duplicate);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.captured_statements.size() == 1U);
                REQUIRE(store.captured_statements.front().name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits login device and token rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("a login transaction is attempted with an invalid token hash")
        {
            auto const rejected = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "plaintext", false, std::nullopt});

            THEN("neither durable side effect is recorded")
            {
                REQUIRE_FALSE(rejected);
                REQUIRE(store.devices.empty());
                REQUIRE(store.access_tokens.empty());
                REQUIRE(store.captured_statements.empty());
            }
        }

        WHEN("a login transaction has a new device and hashed token")
        {
            auto const stored = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});

            THEN("the device and access token become visible together")
            {
                REQUIRE(stored);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.captured_statements.size() == 2U);
                REQUIRE(store.captured_statements[0].name == "insert_device");
                REQUIRE(store.captured_statements[1].name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits room and state-event rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("a room and state event are stored through transaction helpers")
        {
            auto const room_stored = merovingian::database::store_room_with_membership(
                store, {"!room1:example.org", "@alice:example.org"}, {"!room1:example.org", "@alice:example.org"});
            auto const event_stored = merovingian::database::store_event_with_state(
                store,
                {"$event1:example.org", "!room1:example.org", "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})"},
                merovingian::database::PersistentStateEvent{"!room1:example.org", "m.room.member", "@alice:example.org",
                                                            "$event1:example.org"});

            THEN("the related rows and replay statements are all-or-nothing")
            {
                REQUIRE(room_stored);
                REQUIRE(event_stored);
                REQUIRE(store.rooms.size() == 1U);
                REQUIRE(store.memberships.size() == 1U);
                REQUIRE(store.events.size() == 1U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state_transitions.size() == 1U);
                // State-event storage now records both current_state and state_transitions.
                REQUIRE(store.captured_statements.size() == 5U);
            }
        }
    }
}

SCENARIO("SQLite persistent transactions roll back failed statement groups",
         "[database][sqlite][persistence][transaction][review]")
{
    GIVEN("a SQLite store and a transaction with a duplicate room insert")
    {
        auto const sqlite_path = unique_sqlite_path("rollback");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!room1:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!room1:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the first insert is rolled back with the failing insert")
            {
                REQUIRE_FALSE(committed);
                // `restore_sync_stream_id()` may have persisted the sync-stream watermark
                // on startup; any such housekeeping statement is unrelated to this transaction.
                auto const transaction_statements = std::ranges::count_if(
                    store.captured_statements, [](merovingian::database::PreparedStatement const& statement) {
                        return statement.name != "upsert_sync_stream_watermark";
                    });
                REQUIRE(transaction_statements == 0U);
                REQUIRE(reopened.store.rooms.empty());
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

// Complement run 10 (F14): a federated join answered 500 "initial join state
// persistence failed" under load with nothing in the log to say why. A SQLite
// write that fails now says which stage failed, which statement, and SQLite's
// own error, never the bound values (src/database/AGENTS.md rule 2).
SCENARIO("A failed SQLite transaction is logged with its stage, statement and SQLite error",
         "[database][sqlite][persistence][transaction][observability]")
{
    GIVEN("a SQLite store and a transaction whose second insert repeats the first room's ID")
    {
        auto const sqlite_path = unique_sqlite_path("logged-rollback");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!logged:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!logged:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto& logger = merovingian::observability::SingleLog::instance();
            REQUIRE_FALSE(logger.writers_started());
            auto const previous_level = logger.exchange_console_log_level(merovingian::observability::LogLevel::info);
            auto output = std::ostringstream{};
            auto* const previous_buffer = std::cout.rdbuf(output.rdbuf());
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            std::cout.rdbuf(previous_buffer);
            std::ignore = logger.exchange_console_log_level(previous_level);
            auto const logged = output.str();

            THEN("it fails and a warning names the statement and SQLite's constraint error, without the values")
            {
                REQUIRE_FALSE(committed);
                auto lines = std::istringstream{logged};
                auto warning = std::string{};
                for (auto line = std::string{}; std::getline(lines, line);)
                {
                    if (line.find("<WARNING>") != std::string::npos &&
                        line.find("transaction.failed") != std::string::npos)
                    {
                        warning = line;
                    }
                }
                INFO("log: " << logged);
                REQUIRE_FALSE(warning.empty());
                REQUIRE(warning.find("stage=statement") != std::string::npos);
                REQUIRE(warning.find("statement=insert_room_duplicate") != std::string::npos);
                REQUIRE(warning.find("sqlite_code=") != std::string::npos);
                REQUIRE(warning.find("constraint") != std::string::npos);
                REQUIRE(warning.find("@bob:example.org") == std::string::npos);
                REQUIRE(warning.find("!logged:example.org") == std::string::npos);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite hydration fails closed when a row reader cannot be prepared",
         "[database][sqlite][persistence][review]")
{
    GIVEN("a SQLite store whose users table no longer matches the expected row shape")
    {
        auto const sqlite_path = unique_sqlite_path("hydrate");
        std::filesystem::remove(sqlite_path);
        auto initialized = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(initialized.ok);
        auto connection = TestSqliteConnection{sqlite_path};
        REQUIRE(connection.execute("ALTER TABLE users RENAME TO users_bad"));
        REQUIRE(connection.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY)"));

        WHEN("the persistent store is opened again")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());

            THEN("startup rejects the partially readable database")
            {
                REQUIRE_FALSE(reopened.ok);
                REQUIRE(reopened.reason == "unable to hydrate SQLite rows");
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store matches state event JSON with whitespace and upserts current state",
         "[database][persistence][review]")
{
    GIVEN("state events with equivalent formatted JSON")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);
        auto const first_event =
            merovingian::database::store_event(store, {"$event1:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        auto const second_event =
            merovingian::database::store_event(store, {"$event2:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        REQUIRE(first_event);
        REQUIRE(second_event);

        WHEN("the same current-state key is stored twice")
        {
            auto const first_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event1:example.org"});
            auto const second_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event2:example.org"});

            THEN("formatted JSON is accepted and the current-state row is replaced")
            {
                REQUIRE(first_state);
                REQUIRE(second_state);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state.front().event_id == "$event2:example.org");
                REQUIRE(store.state_transitions.size() == 2U);
                // The final statement records the second state transition; the
                // current_state row is updated via the preceding upsert_state.
                // ADR-0064 phase B1: this is now an upsert (ON CONFLICT DO
                // UPDATE), not a bare insert — state_transitions' primary key
                // is (room_id, event_type, state_key, event_id), and state
                // resolution can make an event current again after it was
                // previously superseded, which a bare INSERT would reject as
                // a duplicate row on the second occurrence.
                REQUIRE(store.captured_statements.back().name == "upsert_state_transition");
            }
        }
    }
}

SCENARIO("prepare_store_event_with_state derives previous_event_id from the event graph",
         "[database][persistence][state-transitions]")
{
    GIVEN("a room with a chain of m.room.topic state events")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const room_stored = merovingian::database::store_room_with_membership(
            store, {"!room:example.org", "@alice:example.org"}, {"!room:example.org", "@alice:example.org"});
        REQUIRE(room_stored);

        auto create_event = merovingian::database::PersistentEvent{"$create:example.org",
                                                                   "!room:example.org",
                                                                   "@alice:example.org",
                                                                   R"({"type":"m.room.create","state_key":""})",
                                                                   0U,
                                                                   1U};
        auto const create_stored = merovingian::database::store_event_with_state(
            store, std::move(create_event),
            merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.create", "",
                                                        "$create:example.org"});
        REQUIRE(create_stored);

        auto first_topic = merovingian::database::PersistentEvent{"$topic1:example.org",
                                                                  "!room:example.org",
                                                                  "@alice:example.org",
                                                                  R"({"type":"m.room.topic","state_key":""})",
                                                                  1U,
                                                                  2U,
                                                                  std::vector<std::string>{"$create:example.org"}};
        auto const first_stored = merovingian::database::store_event_with_state(
            store, std::move(first_topic),
            merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.topic", "",
                                                        "$topic1:example.org"});
        REQUIRE(first_stored);

        WHEN("a second topic event names the first as its prev_event")
        {
            auto second_topic = merovingian::database::PersistentEvent{"$topic2:example.org",
                                                                       "!room:example.org",
                                                                       "@alice:example.org",
                                                                       R"({"type":"m.room.topic","state_key":""})",
                                                                       2U,
                                                                       3U,
                                                                       std::vector<std::string>{"$topic1:example.org"}};
            auto const second_stored = merovingian::database::store_event_with_state(
                store, std::move(second_topic),
                merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.topic", "",
                                                            "$topic2:example.org"});

            THEN("the transition records the first topic event as the predecessor")
            {
                REQUIRE(second_stored);
                REQUIRE(store.state_transitions.size() == 3U);
                auto const* transition = merovingian::database::find_state_transition(
                    store, "!room:example.org", "m.room.topic", "", "$topic2:example.org");
                REQUIRE(transition != nullptr);
                REQUIRE(transition->previous_event_id == "$topic1:example.org");
            }
        }
    }
}

SCENARIO("Persisted local event ids are unique across rooms", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with two rooms")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const first_room = merovingian::homeserver::create_room(runtime, login.value);
        auto const second_room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(first_room.ok);
        REQUIRE(second_room.ok);
        auto const initial_event_count = runtime.database.persistent_store.events.size();

        WHEN("one event is sent to each room")
        {
            auto const first_event = merovingian::homeserver::send_event(
                runtime, login.value, first_room.value,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"event-one"}})");
            auto const second_event = merovingian::homeserver::send_event(
                runtime, login.value, second_room.value,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"event-two"}})");

            THEN("event ids do not collide in persistent storage")
            {
                REQUIRE(first_event.ok);
                REQUIRE(second_event.ok);
                REQUIRE(first_event.value != second_event.value);
                REQUIRE(runtime.database.persistent_store.events.size() == initial_event_count + 2U);
                // The last two events are the sent message events; confirm their
                // IDs are distinct (the core non-collision invariant).
                auto const& all_evts = runtime.database.persistent_store.events;
                REQUIRE(all_evts[all_evts.size() - 2U].event_id != all_evts.back().event_id);
            }
        }
    }
}

SCENARIO("Sending a state event mirrors current state", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);
        auto const initial_event_count = runtime.database.persistent_store.events.size();
        auto const initial_state_count = runtime.database.persistent_store.state.size();

        WHEN("a room state event is sent")
        {
            auto const event = merovingian::homeserver::send_event(runtime, login.value, room.value,
                                                                   R"({ "type" : "m.room.topic" , "state_key" : "" })");

            THEN("the event is persisted and materialized as current state")
            {
                REQUIRE(event.ok);
                REQUIRE(runtime.database.persistent_store.events.size() == initial_event_count + 1U);
                REQUIRE(runtime.database.persistent_store.state.size() == initial_state_count + 1U);
                // Verify the topic entry was materialised with the correct event id.
                auto const& state_entries = runtime.database.persistent_store.state;
                auto const topic_it = std::ranges::find_if(state_entries, [](auto const& s) {
                    return s.event_type == "m.room.topic" && s.state_key.empty();
                });
                REQUIRE(topic_it != state_entries.end());
                REQUIRE(topic_it->event_id == event.value);
            }
        }
    }
}

// DB-2 (2026-09-29 audit): the SQLite room-snapshot loader used `event_id IN`
// with one placeholder per loaded event. SQLite's default parameter limit is
// 999, but some builds and test fixtures failed at far smaller counts, and
// the query plan degraded with room size. The relation-table reads must scope
// by room_id through a JOIN instead.
SCENARIO("SQLite room snapshot loads event relations with a room-scoped JOIN", "[database][sqlite][security][db-2]")
{
    GIVEN("a SQLite store holding a room with more than 128 events")
    {
        auto const sqlite_path = unique_sqlite_path("room_snapshot_join");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        if (!opened.ok)
        {
            FAIL(std::string{"open_sqlite_persistent_store failed: "} + opened.reason);
        }
        auto& store = opened.store;

        auto constexpr room_id = "!snapshot:example.org";
        auto constexpr user_id = "@alice:example.org";
        REQUIRE(merovingian::database::store_user(store,
                                                  {std::string{user_id}, "password-hash:v1:1", false, false, false}));
        REQUIRE(merovingian::database::store_room(store, {std::string{room_id}, std::string{user_id}, false}));

        auto constexpr event_count = std::size_t{200U};
        for (auto i = std::size_t{0U}; i < event_count; ++i)
        {
            auto event_id = std::string{"$event-"} + std::to_string(i) + ":example.org";
            auto prev_event_id =
                std::string{"$event-"} + std::to_string((i + event_count - 1U) % event_count) + ":example.org";
            auto event = merovingian::database::PersistentEvent{
                event_id, std::string{room_id},          std::string{user_id},
                "{}",     static_cast<std::uint64_t>(i), static_cast<std::uint64_t>(i)};
            event.status = "normal";
            event.prev_event_ids = {prev_event_id};
            event.auth_event_ids = {"$auth:example.org"};
            event.signatures = {
                {"example.org", "ed25519:test", "fake-signature"}
            };
            REQUIRE(merovingian::database::store_event(store, std::move(event)));
        }

        WHEN("the room snapshot is reloaded")
        {
            REQUIRE(merovingian::database::reload_room(store, room_id));

            THEN("every event still has its prev edges, auth events and signatures reconstructed")
            {
                auto event_with_prev = std::size_t{0U};
                auto event_with_auth = std::size_t{0U};
                auto event_with_signature = std::size_t{0U};
                for (auto const& event : store.events)
                {
                    if (event.room_id != room_id)
                    {
                        continue;
                    }
                    if (!event.prev_event_ids.empty())
                    {
                        ++event_with_prev;
                    }
                    if (!event.auth_event_ids.empty())
                    {
                        ++event_with_auth;
                    }
                    if (!event.signatures.empty())
                    {
                        ++event_with_signature;
                    }
                }
                REQUIRE(event_with_prev == event_count);
                REQUIRE(event_with_auth == event_count);
                REQUIRE(event_with_signature == event_count);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}
