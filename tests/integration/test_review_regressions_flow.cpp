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

[[nodiscard]] auto token_required_registration_config(std::filesystem::path const& token_file)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.registration.enabled = true;
    security.registration.require_token = true;
    security.registration.token_file = token_file.string();
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_secret_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-secret-" + suffix + "-" + std::to_string(now));
}

[[nodiscard]] auto extract_json_string(std::string const& body, std::string_view key) -> std::string
{
    auto const marker = std::string{"\""} + std::string{key} + "\":\"";
    auto const start = body.find(marker);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + marker.size();
    auto const value_end = body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_start, value_end - value_start);
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

class BlockingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit BlockingDiscoveryNetwork(std::chrono::milliseconds delay)
        : delay_{delay}
    {
    }

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        {
            auto lock = std::scoped_lock<std::mutex>{mutex_};
            started_ = true;
        }
        started_cv_.notify_all();
        std::this_thread::sleep_for(delay_);
        return {false, false, {}, "not configured"};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        return {false, {}, "address lookup blocked for regression test"};
    }

    auto wait_until_started() -> void
    {
        auto lock = std::unique_lock<std::mutex>{mutex_};
        auto const started = started_cv_.wait_for(lock, std::chrono::seconds{2}, [this] {
            return started_;
        });
        REQUIRE(started);
    }

private:
    std::chrono::milliseconds delay_{};
    std::mutex mutex_{};
    std::condition_variable started_cv_{};
    bool started_{false};
};

} // namespace

SCENARIO("Public registration enforces configured token policy and never bootstraps admin",
         "[homeserver][security][auth][review]")
{
    GIVEN("a runtime with token-protected registration")
    {
        auto const token_file = unique_secret_path("registration-token");
        {
            auto output = std::ofstream{token_file};
            output << "register-alpha-token\n";
        }
        // Production secret readers require owner-read-only files, not the
        // process umask's default mode for an ofstream fixture.
        std::filesystem::permissions(token_file, std::filesystem::perms::owner_read);
        auto started = merovingian::homeserver::start_client_server(token_required_registration_config(token_file));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("clients register without, with invalid, and with valid registration tokens")
        {
            auto const missing_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});
            auto const invalid_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"wrong"},"username":"alice","password":"CorrectHorse7!"})"});
            auto const accepted = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"register-alpha-token"},"username":"alice","password":"CorrectHorse7!"})"});

            THEN("only the valid token creates a non-admin user")
            {
                // No auth field yields the UI-auth challenge (401); a present
                // but invalid token is rejected outright (403). All three
                // dispatches should complete (not request a long-poll wait).
                REQUIRE(missing_token.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(missing_token.response.status == 401U);
                REQUIRE(invalid_token.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(invalid_token.response.status == 403U);
                REQUIRE(accepted.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(accepted.response.status == 200U);
                REQUIRE_FALSE(runtime.homeserver.database.users.empty());
                REQUIRE_FALSE(runtime.homeserver.database.users.front().admin);
            }
        }

        std::filesystem::remove(token_file);
    }
}

SCENARIO("Inbound federation query/profile answers existing local users even without a stored profile row",
         "[homeserver][federation][query-profile][review][regression]")
{
    GIVEN("a started client-server runtime with a registered local user and a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);

        std::erase_if(runtime.homeserver.database.persistent_store.profiles,
                      [](merovingian::database::PersistentProfile const& profile) {
                          return profile.user_id == "@alice:example.org";
                      });

        auto constexpr remote_origin = "matrix.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "query-profile-review-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));

        WHEN("the remote homeserver sends a signed federation query/profile request")
        {
            auto const target = std::string{"/_matrix/federation/v1/query/profile?user_id=%40alice%3Aexample.org"};
            auto const response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver, {"GET",
                                     target,
                                     x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed,
                                                            "example.org", "GET", target, ""),
                                     {}});

            THEN("the route returns a spec-shaped profile object without the unset fields instead of failing upstream")
            {
                REQUIRE(response.status == 200U);
                // Spec v1.19 query/profile, 200: "If the user does not have a particular
                // field set on their profile, the server MUST either exclude it from the
                // response body or give it the value null." An empty string is neither.
                REQUIRE(response.body.find("displayname") == std::string::npos);
                REQUIRE(response.body.find("avatar_url") == std::string::npos);
            }
        }
    }
}

SCENARIO("Inbound presence and device-list EDUs reject user IDs from a different origin",
         "[homeserver][federation][edu][origin-check][review][regression]")
{
    GIVEN("a started client-server runtime with a local user and a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(registered.response.status == 200U);

        auto constexpr remote_origin = "remote.example.org";
        auto constexpr remote_key_id = "ed25519:auto";
        auto constexpr remote_key_seed = "origin-check-review-seed";
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_runtime(remote_origin, remote_key_id, remote_key_seed));

        auto const presence_content =
            R"({"push":[{"user_id":"@mallory:evil.example.org","presence":"online","status_msg":"spoofed"}]})";
        auto const presence_transaction =
            merovingian::federation::build_edu_transaction_body(remote_origin, "m.presence", presence_content);
        REQUIRE(presence_transaction.has_value());
        auto const presence_target = std::string{"/_matrix/federation/v1/send/txn-presence-1"};

        auto const device_list_content =
            R"({"user_id":"@mallory:evil.example.org","device_id":"DEVICE1","stream_id":9})";
        auto const device_list_transaction = merovingian::federation::build_edu_transaction_body(
            remote_origin, "m.device_list_update", device_list_content);
        REQUIRE(device_list_transaction.has_value());
        auto const device_list_target = std::string{"/_matrix/federation/v1/send/txn-device-list-1"};

        WHEN("the remote sends EDUs whose user_ids claim a different server")
        {
            auto const presence_response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver,
                {"PUT", presence_target,
                 x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed, "example.org", "PUT",
                                        presence_target, *presence_transaction),
                 *presence_transaction});
            auto const device_list_response = merovingian::homeserver::handle_federation_http_request(
                runtime.homeserver,
                {"PUT", device_list_target,
                 x_matrix_authorization(remote_origin, remote_key_id, remote_key_seed, "example.org", "PUT",
                                        device_list_target, *device_list_transaction),
                 *device_list_transaction});

            THEN("no spoofed presence or device-list side effects are recorded")
            {
                REQUIRE(presence_response.status == 200U);
                REQUIRE(device_list_response.status == 200U);
                REQUIRE(std::ranges::none_of(runtime.homeserver.database.persistent_store.presence_states,
                                             [](auto const& state) {
                                                 return state.user_id == "@mallory:evil.example.org";
                                             }));
                REQUIRE(std::ranges::none_of(runtime.homeserver.database.persistent_store.device_list_changes,
                                             [](auto const& change) {
                                                 return change.subject_user_id == "@mallory:evil.example.org";
                                             }));
            }
        }
    }
}

SCENARIO("A blocking remote join does not serialize unrelated client requests",
         "[homeserver][locking][review][regression]")
{
    GIVEN("a started client-server runtime with a remote join blocked in discovery")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);
        auto const login_response = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_response.response.status == 200U);
        auto const access_token = extract_json_string(login_response.response.body, "access_token");

        auto discovery = std::make_unique<BlockingDiscoveryNetwork>(std::chrono::milliseconds{250});
        auto* discovery_ptr = discovery.get();
        runtime.homeserver.discovery_network = std::move(discovery);

        auto join_response = merovingian::homeserver::LocalHttpResponse{};
        auto join_thread = std::thread{[&] {
            join_response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!blocked:remote.example.org/join", access_token, {}},
                merovingian::homeserver::HttpDispatchMode::client_server);
        }};

        discovery_ptr->wait_until_started();

        WHEN("another client request arrives while discovery is still blocked")
        {
            auto const before = std::chrono::steady_clock::now();
            auto const versions = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}},
                merovingian::homeserver::HttpDispatchMode::client_server);
            auto const elapsed = std::chrono::steady_clock::now() - before;

            join_thread.join();

            THEN("the unrelated request completes without waiting for the remote join to finish")
            {
                REQUIRE(versions.status == 200U);
                REQUIRE(elapsed < std::chrono::milliseconds{150});
                REQUIRE(join_response.status == 502U);
                REQUIRE(join_response.body.find("make_join failed") != std::string::npos);
            }
        }
    }
}

// Regression: leave_room returned 403 "user is not joined or invited" when the
// membership row was absent (server restarted between store_room and store_membership
// during a federated join). The row should be recovered from the current_state table
// before the membership check, allowing the leave to proceed.
SCENARIO("leave_room recovers missing membership row from current state before rejecting with 403",
         "[homeserver][rooms][leave][regression][recovery]")
{
    GIVEN("a started runtime with a registered user whose membership row is absent "
          "but current_state has a join event for a remote room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        // Register and log in the user.
        auto const reg_resp = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("bob", "SecurePass1!")});
        REQUIRE(reg_resp.response.status == 200U);
        auto const login_resp = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"SecurePass1!","device_id":"DEV1"})"});
        REQUIRE(login_resp.response.status == 200U);
        auto const access_token = extract_json_string(login_resp.response.body, "access_token");

        // Simulate a partial join: room stored, join state event stored, but NO
        // membership row — this is the state left behind by a mid-join server restart.
        auto constexpr room_id = "!partialroom:remote.example.org";
        auto constexpr user_id = "@bob:example.org";
        auto constexpr event_id = "$join_ev1:remote.example.org";
        auto const join_event_json =
            std::string{R"({"type":"m.room.member","state_key":")" + std::string{user_id} + R"(","sender":")" +
                        std::string{user_id} + R"(","room_id":")" + std::string{room_id} +
                        R"(","origin_server_ts":1700000000000,"depth":1,)"
                        R"("auth_events":[],"prev_events":[],)"
                        R"("content":{"membership":"join"}})"};
        {
            auto& store = rt.homeserver.database.persistent_store;
            store.rooms.push_back({std::string{room_id}, std::string{user_id}});
            auto pe = merovingian::database::PersistentEvent{};
            pe.event_id = event_id;
            pe.room_id = room_id;
            pe.sender_user_id = user_id;
            pe.json = join_event_json;
            pe.stream_ordering = rt.homeserver.database.next_stream_ordering++;
            auto state = std::optional<merovingian::database::PersistentStateEvent>{
                merovingian::database::PersistentStateEvent{std::string{room_id}, "m.room.member", std::string{user_id},
                                                            std::string{event_id}}
            };
            std::ignore = merovingian::database::store_event_with_state(store, std::move(pe), state);
            // Deliberately do NOT store a membership row.
        }

        WHEN("the user attempts to leave the remote room")
        {
            // outbound_client is null → federation fails → 502 expected.
            // The key assertion is that we do NOT get 403 "user is not joined",
            // which would mean the recovery logic did not fire.
            auto const result = merovingian::homeserver::leave_room(rt.homeserver, access_token, room_id);

            THEN("the response is not 403 — membership was recovered from state")
            {
                // 502 = federation not available (null outbound client), which means
                // the recovery path fired and we reached the federated-leave attempt.
                REQUIRE(result.status != 403U);
                REQUIRE(result.status != 404U);
            }
        }
    }
}

// Regression: leave_room for a remote room called persist_membership_transition
// (local-only) instead of making outbound make_leave / send_leave federation calls.
// Verify that the federated leave path is entered by observing a 502 when the
// federation infrastructure is unavailable.
SCENARIO("leave_room takes the federated make_leave/send_leave path for remote rooms",
         "[homeserver][rooms][leave][federation][regression]")
{
    GIVEN("a started runtime with a user joined to a remote room via a persisted membership row")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const reg_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("carol", "SecurePass2!")});
        REQUIRE(reg_resp.response.status == 200U);
        auto const login_resp = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@carol:example.org"},"password":"SecurePass2!","device_id":"DEV2"})"});
        REQUIRE(login_resp.response.status == 200U);
        auto const access_token = extract_json_string(login_resp.response.body, "access_token");

        auto constexpr room_id = "!fedroom:remote.example.org";
        auto constexpr user_id = "@carol:example.org";

        {
            auto& store = rt.homeserver.database.persistent_store;
            store.rooms.push_back({std::string{room_id}, std::string{user_id}});
            auto const stream = rt.homeserver.database.next_stream_ordering++;
            std::ignore = merovingian::database::store_membership(
                store, {std::string{room_id}, std::string{user_id}, "join", stream});
        }

        WHEN("the user leaves and the federation infrastructure is unavailable")
        {
            // Ensure outbound_client and discovery_network are null so the
            // federation call returns {false, "federation not available"}.
            rt.homeserver.outbound_client = nullptr;
            rt.homeserver.discovery_network = nullptr;

            auto const result = merovingian::homeserver::leave_room(rt.homeserver, access_token, room_id);

            THEN("the call fails with 502 indicating the federated leave path was taken")
            {
                // 403 would mean the membership check failed (local path entered).
                // 502 means make_leave was attempted and the remote was unreachable.
                REQUIRE(result.status == 502U);
                REQUIRE(result.ok == false);
                // The reason must mention make_leave, not a membership mismatch.
                REQUIRE(result.reason.find("make_leave") != std::string::npos);
            }
        }
    }
}

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
