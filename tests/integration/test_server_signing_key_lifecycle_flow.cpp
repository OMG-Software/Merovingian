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

namespace
{

[[nodiscard]] auto signing_lifecycle_config() -> merovingian::config::Config
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

[[nodiscard]] auto now_ms() -> std::uint64_t
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// Simulates a server that has been running longer than the published key window:
// every stored key's valid_until_ts is moved into the past. Nothing else about the
// key material changes - the secret is still valid and still the server's identity.
auto lapse_all_signing_key_windows(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    auto const past = now_ms() - std::uint64_t{60U * 1000U};
    for (auto& key : runtime.database.persistent_store.server_signing_keys)
    {
        key.valid_until_ts = past;
    }
}

[[nodiscard]] auto json_string_field(std::string const& body, std::string const& field) -> std::string
{
    auto const key = "\"" + field + "\":\"";
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

// Merovingian invariant (client-visible):
// A server whose uptime exceeds the published key window must keep accepting locally
// composed events. This is the exact failure reported by mobile clients: every
// PUT /rooms/{roomId}/send/... returned 403 "event authorization or signing failed"
// because the preferred key had been silently replaced behind the signing provider.
SCENARIO("Sending a room event still succeeds after the published key window lapses",
         "[homeserver][signing][client-server][rooms]")
{
    GIVEN("a logged-in user in a room on a server whose key window has lapsed")
    {
        auto started = merovingian::homeserver::start_client_server(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = json_string_field(login.response.body, "access_token");

        auto const created = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(created.response.status == 200U);
        auto const room = json_string_field(created.response.body, "room_id");

        lapse_all_signing_key_windows(runtime.homeserver);

        WHEN("the user sends a message")
        {
            auto const sent = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/txn-lapsed-1", token,
                          R"({"msgtype":"m.text","body":"hello"})"});

            THEN("the event is accepted and assigned an event id")
            {
                REQUIRE(sent.response.status == 200U);
                REQUIRE(json_string_field(sent.response.body, "event_id").starts_with("$"));
            }
        }
    }
}
