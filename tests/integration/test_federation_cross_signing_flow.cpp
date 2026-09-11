// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cross-signing across federation, end to end.
//
// Regression cover for "devices of users on other servers always show as
// unverified". A client decides whether a device is verified by checking it
// against its owner's self-signing key, and whether a user is verified by
// checking its own user-signing signature over that user's master key. Every
// piece of that chain was lost somewhere between two servers:
//
//   * the /keys/query federation proxy kept only `device_keys` from the
//     remote /user/keys/query response and discarded `master_keys` and
//     `self_signing_keys`;
//   * the requester's own user-signing signature over a remote master key was
//     never merged back in;
//   * inbound m.signing_key_update EDUs were dropped as an unknown type;
//   * outbound, m.signing_key_update was never sent at all.
//
// Spec: Matrix Client-Server API v1.19, POST /_matrix/client/v3/keys/query
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysquery
// Spec: Matrix Server-Server API v1.19, POST /_matrix/federation/v1/user/keys/query
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeysquery
// Spec: Matrix Server-Server API v1.19, m.signing_key_update
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#msigning_key_update

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

using namespace merovingian::tests;

namespace
{

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest,
    // and the /keys/query proxy signs its federation request with it.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

struct RegisteredUser final
{
    std::string user_id{};
    std::string access_token{};
};

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart)
    -> RegisteredUser
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* user_id = string_member(body, "user_id");
    auto const* token = string_member(body, "access_token");
    REQUIRE(user_id != nullptr);
    REQUIRE(token != nullptr);
    return {*user_id, *token};
}

// signatures[signer][key_id] of a key object, or nullptr when any level is missing.
[[nodiscard]] auto signature_of(merovingian::canonicaljson::Object const& key_object, std::string_view signer,
                                std::string_view key_id) -> std::string const*
{
    auto const* signatures = object_member_as_object(key_object, "signatures");
    auto const* by_signer = signatures == nullptr ? nullptr : object_member_as_object(*signatures, signer);
    return by_signer == nullptr ? nullptr : string_member(*by_signer, key_id);
}

// What bob's server answers to POST /_matrix/federation/v1/user/keys/query:
// bob's device, cross-signed by his self-signing key, and his master and
// self-signing keys. It also tries to answer for a user on a different
// server, which it has no authority over.
[[nodiscard]] auto bobs_server_response() -> std::string
{
    return std::string{
        R"({"device_keys":{"@bob:remote.example.org":{"BDEV":{"algorithms":["m.megolm.v1.aes-sha2"],"device_id":"BDEV","keys":{"ed25519:BDEV":"bdev"},"signatures":{"@bob:remote.example.org":{"ed25519:BDEV":"bdev-self","ed25519:BOBSSK":"bob-ssk-sig"}},"user_id":"@bob:remote.example.org"}},)"
        R"("@victim:elsewhere.example.org":{"FORGED":{"device_id":"FORGED","keys":{"ed25519:FORGED":"x"},"user_id":"@victim:elsewhere.example.org"}}},)"
        R"("master_keys":{"@bob:remote.example.org":{"keys":{"ed25519:BOBMASTER":"BOBMASTER"},"signatures":{"@bob:remote.example.org":{"ed25519:BDEV":"bdev-msk-sig"}},"usage":["master"],"user_id":"@bob:remote.example.org"},)"
        R"("@victim:elsewhere.example.org":{"keys":{"ed25519:FORGEDMASTER":"FORGEDMASTER"},"usage":["master"],"user_id":"@victim:elsewhere.example.org"}},)"
        R"("self_signing_keys":{"@bob:remote.example.org":{"keys":{"ed25519:BOBSSK":"BOBSSK"},"signatures":{"@bob:remote.example.org":{"ed25519:BOBMASTER":"bob-msk-ssk-sig"}},"usage":["self_signing"],"user_id":"@bob:remote.example.org"}}})"};
}

// A dispatch worker that is never started, so every EDU the server enqueues
// stays in its durable queue (store.federation_transactions) for the test to
// read, with no worker thread racing the read. Installed before anything
// wires federation, which then reuses it instead of starting its own.
auto install_unstarted_dispatch_worker(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    REQUIRE(runtime.homeserver.outbound_client != nullptr);
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = runtime.homeserver.config.server().server_name;
    config.key_id = "ed25519:test";
    runtime.homeserver.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), *runtime.homeserver.outbound_client,
        [](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        },
        merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
        &runtime.homeserver.database.persistent_store);
}

// Bodies of the queued federation transactions addressed to `destination`
// that carry an EDU of `edu_type`.
[[nodiscard]] auto queued_edus(merovingian::homeserver::ClientServerRuntime const& runtime,
                               std::string_view destination, std::string_view edu_type) -> std::vector<std::string>
{
    auto const marker = std::string{R"("edu_type":")"} + std::string{edu_type} + "\"";
    auto bodies = std::vector<std::string>{};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name == destination && transaction.body.find(marker) != std::string::npos)
        {
            bodies.push_back(transaction.body);
        }
    }
    return bodies;
}

[[nodiscard]] auto cross_signing_upload_body(std::string_view user_id, bool include_public_keys) -> std::string
{
    auto const user = std::string{user_id};
    auto body = std::string{"{"};
    if (include_public_keys)
    {
        body += R"("master_key":{"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"usage":["master"],"user_id":")" + user +
                R"("},"self_signing_key":{"keys":{"ed25519:ALICESSK":"ALICESSK"},"signatures":{")" + user +
                R"(":{"ed25519:ALICEMASTER":"msk-sig"}},"usage":["self_signing"],"user_id":")" + user + R"("},)";
    }
    body += R"("user_signing_key":{"keys":{"ed25519:ALICEUSK":"ALICEUSK"},"signatures":{")" + user +
            R"(":{"ed25519:ALICEMASTER":"msk-usk-sig"}},"usage":["user_signing"],"user_id":")" + user + R"("},)";
    body += R"("auth":{"type":"m.login.password","password":"CorrectHorse7!"}})";
    return body;
}

[[nodiscard]] auto sync_next_batch(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                   std::string const& since)
    -> std::pair<std::string, merovingian::canonicaljson::Object>
{
    auto const target =
        since.empty() ? std::string{"/_matrix/client/v3/sync"} : std::string{"/_matrix/client/v3/sync?since="} + since;
    auto const response = merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}});
    REQUIRE(response.response.status == 200U);
    auto body = parse_object(response.response.body);
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    return {*next_batch, std::move(body)};
}

[[nodiscard]] auto device_lists_changed_contains(merovingian::canonicaljson::Object const& sync_body,
                                                 std::string_view user_id) -> bool
{
    auto const* device_lists = object_member_as_object(sync_body, "device_lists");
    auto const* changed = device_lists == nullptr ? nullptr : object_member_as_array(*device_lists, "changed");
    if (changed == nullptr)
    {
        return false;
    }
    return std::ranges::any_of(*changed, [user_id](merovingian::canonicaljson::Value const& value) {
        auto const* text = std::get_if<std::string>(&value.storage());
        return text != nullptr && *text == user_id;
    });
}

} // namespace

SCENARIO("A key query for a remote user returns that user's cross-signing keys",
         "[integration][federation][e2ee][keys][cross-signing][regression]")
{
    GIVEN("alice has verified bob on another server, and bob's server answers key queries")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const carol = register_user(runtime, "carol");

        // Alice's client uploads her user-signing signature over bob's master
        // key, keyed by its bare base64 public key as the spec's example does.
        auto const verification = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/signatures/upload", alice.access_token,
             R"({"@bob:remote.example.org":{"BOBMASTER":{"keys":{"ed25519:BOBMASTER":"BOBMASTER"},"signatures":{")" +
                 alice.user_id +
                 R"(":{"ed25519:ALICEUSK":"alice-usk-sig"}},"usage":["master"],"user_id":"@bob:remote.example.org"}}})"});
        REQUIRE(verification.response.status == 200U);

        auto const certificate = tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        runtime.homeserver.test_forced_outbound_resolution[std::string{remote_server}] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

        // Serves exactly one /user/keys/query; built on this thread, only
        // served from the other, so no assertion runs off the main thread.
        auto const http_response = tls_mock::json_http_response("200 OK", bobs_server_response());
        auto server_thread = std::thread{[&]() {
            tls_mock::run_one_shot_tls_server(acceptor, *tls_context.context, http_response);
        }};
        auto const server_join = tls_mock::ScopedThreadJoin{server_thread};

        auto const query_bob = std::string{R"({"device_keys":{"@bob:remote.example.org":[]}})"};

        WHEN("alice queries bob's keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", alice.access_token, query_bob});
            REQUIRE(response.response.status == 200U);
            auto const body = parse_object(response.response.body);

            THEN("bob's master and self-signing keys are returned, so his devices can be checked against them")
            {
                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                auto const* bob_master = object_member_as_object(*master_keys, bob);
                REQUIRE(bob_master != nullptr);
                // Bob's own signature over his master key is passed through untouched.
                REQUIRE(signature_of(*bob_master, bob, "ed25519:BDEV") != nullptr);

                auto const* self_signing_keys = object_member_as_object(body, "self_signing_keys");
                REQUIRE(self_signing_keys != nullptr);
                auto const* bob_ssk = object_member_as_object(*self_signing_keys, bob);
                REQUIRE(bob_ssk != nullptr);
                REQUIRE(signature_of(*bob_ssk, bob, "ed25519:BOBMASTER") != nullptr);

                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* bob_devices = object_member_as_object(*device_keys, bob);
                REQUIRE(bob_devices != nullptr);
                auto const* bob_device = object_member_as_object(*bob_devices, "BDEV");
                REQUIRE(bob_device != nullptr);
                REQUIRE(signature_of(*bob_device, bob, "ed25519:BOBSSK") != nullptr);
            }

            AND_THEN("bob's master key carries alice's own verification signature")
            {
                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                auto const* bob_master = object_member_as_object(*master_keys, bob);
                REQUIRE(bob_master != nullptr);
                auto const* alice_sig = signature_of(*bob_master, alice.user_id, "ed25519:ALICEUSK");
                REQUIRE(alice_sig != nullptr);
                REQUIRE(*alice_sig == "alice-usk-sig");
            }

            AND_THEN("nothing bob's server said about a user on another server is passed on")
            {
                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                REQUIRE(object_member(*device_keys, "@victim:elsewhere.example.org") == nullptr);
                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                REQUIRE(object_member(*master_keys, "@victim:elsewhere.example.org") == nullptr);
            }
        }

        WHEN("carol, who has not verified bob, queries bob's keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", carol.access_token, query_bob});
            REQUIRE(response.response.status == 200U);
            auto const body = parse_object(response.response.body);

            THEN("she gets bob's master key without alice's private verification signature")
            {
                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                auto const* bob_master = object_member_as_object(*master_keys, bob);
                REQUIRE(bob_master != nullptr);
                REQUIRE(signature_of(*bob_master, alice.user_id, "ed25519:ALICEUSK") == nullptr);
            }
        }
    }
}

SCENARIO("Publishing cross-signing keys tells the servers alice shares rooms with",
         "[integration][federation][e2ee][keys][cross-signing][edu][regression]")
{
    GIVEN("alice shares a room with bob on another server")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        runtime.homeserver.database.rooms.push_back({
            "!shared:example.org", alice.user_id, {alice.user_id, std::string{bob}},
              {}
        });

        WHEN("alice uploads her master, self-signing and user-signing keys")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/device_signing/upload", alice.access_token,
                          cross_signing_upload_body(alice.user_id, true)});
            REQUIRE(upload.response.status == 200U);

            THEN("bob's server is sent an m.signing_key_update with her public cross-signing keys")
            {
                auto const updates = queued_edus(runtime, remote_server, "m.signing_key_update");
                REQUIRE(updates.size() == 1U);
                REQUIRE(updates.front().find("ALICEMASTER") != std::string::npos);
                REQUIRE(updates.front().find("ALICESSK") != std::string::npos);
                // The user-signing key is private to alice and never leaves her server.
                REQUIRE(updates.front().find("ALICEUSK") == std::string::npos);
            }
        }

        WHEN("alice uploads only a new user-signing key")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/device_signing/upload", alice.access_token,
                          cross_signing_upload_body(alice.user_id, false)});
            REQUIRE(upload.response.status == 200U);

            THEN("no m.signing_key_update is sent, because nothing remote servers can see changed")
            {
                REQUIRE(queued_edus(runtime, remote_server, "m.signing_key_update").empty());
            }
        }
    }
}

SCENARIO("A remote user's cross-signing key change reaches local clients",
         "[integration][federation][e2ee][keys][cross-signing][edu][regression]")
{
    GIVEN("alice is syncing, and federation is wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        REQUIRE(runtime.homeserver.federation.edu_sink != nullptr);
        auto const since = sync_next_batch(runtime, alice.access_token, {}).first;

        auto const content = std::string{
            R"({"master_key":{"keys":{"ed25519:NEWMASTER":"NEWMASTER"},"usage":["master"],"user_id":"@bob:remote.example.org"},"user_id":"@bob:remote.example.org"})"};

        WHEN("bob's server reports that bob reset his cross-signing keys")
        {
            auto const envelope =
                merovingian::federation::parse_inbound_edu_envelope("m.signing_key_update", remote_server, content);
            REQUIRE(envelope.has_value());
            auto const disposition = runtime.homeserver.federation.edu_sink(*envelope);

            THEN("the EDU is accepted and alice's next sync lists bob in device_lists.changed")
            {
                REQUIRE(disposition.status == merovingian::federation::EduDispositionStatus::accepted);
                auto const body = sync_next_batch(runtime, alice.access_token, since).second;
                // Spec: device_lists.changed prompts the client to /keys/query
                // bob again and pick up his new cross-signing identity.
                REQUIRE(device_lists_changed_contains(body, bob));
            }
        }

        WHEN("a different server claims bob reset his cross-signing keys")
        {
            auto const envelope = merovingian::federation::parse_inbound_edu_envelope("m.signing_key_update",
                                                                                      "evil.example.org", content);
            REQUIRE(envelope.has_value());
            auto const disposition = runtime.homeserver.federation.edu_sink(*envelope);

            THEN("the EDU is rejected and alice is not told anything changed")
            {
                REQUIRE(disposition.status == merovingian::federation::EduDispositionStatus::rejected_invalid);
                auto const body = sync_next_batch(runtime, alice.access_token, since).second;
                REQUIRE_FALSE(device_lists_changed_contains(body, bob));
            }
        }
    }
}
