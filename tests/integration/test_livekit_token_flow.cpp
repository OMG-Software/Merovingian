// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The built-in MatrixRTC token service (MSC4195; ADR-0829, ADR-0830): POST .../rtc/livekit/get_token driven through
// handle_client_server_request, with HomeserverRuntime::test_livekit_perform standing in for LiveKit. No network.

#include "../support/ConsoleLogCapture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/LiveKitTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "../support/TlsMockServer.hpp"
#include "../support/TlsTestCertificate.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/crypto/VerifiedHs256Token.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientOutboundProxy.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"
#include "merovingian/homeserver/LiveKitTokenService.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/TestOnlyForcedOutboundResolution.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/homeserver/TlsServerContextResult.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/net/TcpAcceptor.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
using namespace merovingian::tests;
using namespace merovingian::tests::livekit;

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto carol = std::string_view{"@carol:remote.example.org"};

// Puts `user_id` joined in the room's current state, as an accepted federated join would.
auto seed_remote_join(hs::ClientServerRuntime& runtime, std::string const& room_id, std::string_view const user_id)
    -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    auto const event_id = "$join-of-" + std::string{user_id};
    auto const json = R"({"content":{"membership":"join"},"event_id":")" + event_id + R"(","room_id":")" + room_id +
                      R"(","sender":")" + std::string{user_id} + R"(","state_key":")" + std::string{user_id} +
                      R"(","type":"m.room.member"})";
    store.events.push_back({event_id, room_id, std::string{user_id}, json, 9U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", std::string{user_id}, event_id});
    store.memberships.push_back({room_id, std::string{user_id}, "join", 0U});
    auto* room = hs::find_local_room(runtime.homeserver.database, room_id);
    REQUIRE(room != nullptr);
    std::ignore = room->members.add(std::string{user_id});
}

// Makes the room's current `m.room.server_acl` allow every server but `denied`.
auto seed_server_acl(hs::ClientServerRuntime& runtime, std::string const& room_id, std::string_view const denied)
    -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    auto const event_id = std::string{"$server-acl"};
    auto const json = R"({"content":{"allow":["*"],"allow_ip_literals":false,"deny":[")" + std::string{denied} +
                      R"("]},"event_id":")" + event_id + R"(","room_id":")" + room_id +
                      R"(","sender":"@alice:example.org","state_key":"","type":"m.room.server_acl"})";
    store.events.push_back({event_id, room_id, "@alice:example.org", json, 11U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.server_acl", "", event_id});
}

// MSC4195's federation body, as `origin` would send it.
[[nodiscard]] auto federation_body(std::string_view const room_id, std::string_view const user_id,
                                   std::string_view const url = sfu_url) -> std::string
{
    return R"({"url":")" + std::string{url} + R"(","room_id":")" + std::string{room_id} +
           R"(","slot_id":"m.call#room","member_id":"DEVICEID_member","user_id":")" + std::string{user_id} + R"("})";
}

// What main answers a federated request it has admitted, judged under the runtime lock as the relay calls it.
[[nodiscard]] auto federated(hs::ClientServerRuntime& runtime, std::string_view const origin, std::string const& body)
    -> hs::OperationResult
{
    auto const guard = hs::RuntimeLock{runtime.homeserver.mutex};
    return hs::issue_federation_livekit_token(runtime.homeserver, origin, body);
}

// Another server answering the relayed get_token once with `response`; the request it saw is kept.
class RemoteTokenServer final
{
public:
    RemoteTokenServer(hs::ClientServerRuntime& runtime, std::string response)
        : m_response{std::move(response)}
        , m_certificate{tls_mock::write_test_tls_certificate()}
        , m_tls{hs::make_tls_server_context(m_certificate.certificate_file, m_certificate.private_key_file)}
    {
        REQUIRE(m_tls.ok());
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        runtime.homeserver.test_forced_outbound_resolution[std::string{remote_server}] =
            hs::TestOnlyForcedOutboundResolution{
                "localhost", m_acceptor.bound_port(), {"127.0.0.1"}, m_certificate.certificate_pem};
        m_thread = std::thread{[this]() {
            serve();
        }};
    }

    ~RemoteTokenServer()
    {
        std::ignore = finish();
    }

    RemoteTokenServer(RemoteTokenServer const&) = delete;
    auto operator=(RemoteTokenServer const&) -> RemoteTokenServer& = delete;
    RemoteTokenServer(RemoteTokenServer&&) = delete;
    auto operator=(RemoteTokenServer&&) -> RemoteTokenServer& = delete;

    // Joins the serving thread; the request it saw is readable afterwards.
    [[nodiscard]] auto finish() -> std::string const&
    {
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        return m_captured;
    }

private:
    // One connection: the whole request, headers and Content-Length body, then the response.
    auto serve() noexcept -> void
    {
        auto const client_fd = tls_mock::accept_loopback(m_acceptor, 5000);
        if (client_fd < 0)
        {
            return;
        }
        auto const owned = merovingian::core::SocketHandle{client_fd};
        auto tls = hs::accept_tls_connection(*m_tls.context, client_fd, 5000);
        if (!tls.connection.has_value())
        {
            return;
        }
        auto buffer = std::array<char, 4096>{};
        auto expected = std::string::npos;
        while (expected == std::string::npos || m_captured.size() < expected)
        {
            auto const bytes_read = tls.connection->read(buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                break;
            }
            m_captured.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            auto const headers_end = m_captured.find("\r\n\r\n");
            if (expected == std::string::npos && headers_end != std::string::npos)
            {
                auto headers = m_captured.substr(0U, headers_end);
                std::ranges::transform(headers, headers.begin(), [](unsigned char const c) {
                    return static_cast<char>(std::tolower(c));
                });
                auto const length_at = headers.find("\r\ncontent-length:");
                auto const length =
                    length_at == std::string::npos
                        ? std::size_t{0U}
                        : static_cast<std::size_t>(std::strtoul(headers.c_str() + length_at + 17U, nullptr, 10));
                expected = headers_end + 4U + length;
            }
        }
        std::ignore = tls.connection->write(m_response);
    }

    std::string m_response;
    tls_mock::TlsTestCertificate m_certificate;
    hs::TlsServerContextResult m_tls;
    merovingian::net::TcpAcceptor m_acceptor{};
    std::string m_captured{};
    std::thread m_thread{};
};

// alice's body asking for a token for the remote server's SFU.
[[nodiscard]] auto relay_body(std::string_view const room_id) -> std::string
{
    return R"({"url":"wss://sfu.remote.example.org","room_id":")" + std::string{room_id} +
           R"(","slot_id":"m.call#room","member_id":"DEVICEID_member","server_name":")" + std::string{remote_server} +
           R"("})";
}

} // namespace

SCENARIO("A joined user gets a LiveKit token for this server's SFU, and the room is created first",
         "[homeserver][livekit][rtc][client-server]")
{
    GIVEN("alice, joined to a room, and the built-in token service")
    {
        auto fixture = LiveKitFixture{};
        auto const path = std::string{GENERATE(stable_path, unstable_path)};

        WHEN("alice asks for a token on " + path)
        {
            auto const answer =
                request(fixture.runtime(), "POST", path, fixture.alice_token, token_body(fixture.room_id));

            THEN("the answer is one jwt, signed with the API secret, for the MSC4195 names and no more")
            {
                REQUIRE(answer.status == 200U);
                auto const body = parse_object(answer.body);
                REQUIRE(body.size() == 1U);
                auto const* jwt = string_member(body, "jwt");
                REQUIRE(jwt != nullptr);
                auto const payload = verified_payload(*jwt);
                auto const room_name = hs::livekit_room_name(fixture.room_id, "m.call#room");
                auto const identity = hs::livekit_participant_identity("@alice:example.org", "DEVICEID_member");
                REQUIRE((room_name.has_value() && identity.has_value()));
                auto const* iss = string_member(payload, "iss");
                auto const* sub = string_member(payload, "sub");
                REQUIRE((iss != nullptr && sub != nullptr));
                CHECK(*iss == api_key);
                CHECK(*sub == *identity);
                auto const* nbf = int_member(payload, "nbf");
                auto const* exp = int_member(payload, "exp");
                REQUIRE((nbf != nullptr && exp != nullptr));
                CHECK(*exp - *nbf == 600);
                auto const* video = object_member_as_object(payload, "video");
                REQUIRE(video != nullptr);
                auto const* room = string_member(*video, "room");
                REQUIRE(room != nullptr);
                CHECK(*room == *room_name);
                auto const* join = bool_member(*video, "roomJoin");
                auto const* publish = bool_member(*video, "canPublish");
                auto const* publish_data = bool_member(*video, "canPublishData");
                auto const* subscribe = bool_member(*video, "canSubscribe");
                REQUIRE((join != nullptr && publish != nullptr && publish_data != nullptr && subscribe != nullptr));
                CHECK((*join && *publish && *publish_data && *subscribe));
                // Exactly those five grants: never roomCreate, roomAdmin, hidden, or anything else.
                CHECK(video->size() == 5U);
                // Nothing the SFU sees names the Matrix user, device or room.
                CHECK(jwt->find("alice") == std::string::npos);
                auto const secret = secret_bytes(api_secret);
                auto const decoded =
                    merovingian::crypto::verify_hs256_token(*jwt, std::span<std::uint8_t const>{secret});
                REQUIRE(decoded.has_value());
                CHECK(decoded->payload_json.find("alice") == std::string::npos);
                CHECK(decoded->payload_json.find("DEVICEID") == std::string::npos);
                CHECK(decoded->payload_json.find(fixture.room_id) == std::string::npos);
            }

            THEN("CreateRoom went to the configured API address, with a roomCreate-only token of its own")
            {
                REQUIRE(answer.status == 200U);
                REQUIRE(fixture.mock().requests.size() == 1U);
                auto const& call = fixture.mock().requests.front();
                CHECK(call.method == "POST");
                CHECK(call.url == "https://sfu-api.example.org:443/twirp/livekit.RoomService/CreateRoom");
                CHECK_FALSE(call.allow_cleartext_http);
                CHECK(call.max_response_body_bytes == 16U * 1024U);
                CHECK(call.total_timeout_seconds > 0U);
                CHECK(call.total_timeout_seconds <= 10U);
                auto const room_name = hs::livekit_room_name(fixture.room_id, "m.call#room");
                REQUIRE(room_name.has_value());
                CHECK(call.body == R"({"name":")" + *room_name + R"(","empty_timeout":300,"departure_timeout":20})");
                CHECK(header_value(call, "Content-Type") == std::optional<std::string>{"application/json"});
                auto const authorization = header_value(call, "Authorization");
                REQUIRE(authorization.has_value());
                REQUIRE(authorization->starts_with("Bearer "));
                auto const payload = verified_payload(std::string_view{*authorization}.substr(7U));
                CHECK(string_member(payload, "sub") == nullptr);
                auto const* video = object_member_as_object(payload, "video");
                REQUIRE(video != nullptr);
                CHECK(video->size() == 1U);
                auto const* create = bool_member(*video, "roomCreate");
                REQUIRE(create != nullptr);
                CHECK(*create);
                auto const* nbf = int_member(payload, "nbf");
                auto const* exp = int_member(payload, "exp");
                REQUIRE((nbf != nullptr && exp != nullptr));
                CHECK(*exp - *nbf == 60);
            }
        }
    }
}

SCENARIO("A token goes only to a user this server finds joined to the room", "[homeserver][livekit][rtc][negative]")
{
    GIVEN("alice in a room, and bob registered")
    {
        auto fixture = LiveKitFixture{};

        WHEN("bob, never in the room, asks for a token for it")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                        token_body(fixture.room_id));
            auto const unknown = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                         token_body("!nosuchroom:example.org"));

            THEN("both are the same 403, and LiveKit is never called")
            {
                CHECK(answer.status == 403U);
                CHECK(errcode_of(answer) == "M_FORBIDDEN");
                CHECK(unknown.status == 403U);
                CHECK(unknown.body == answer.body);
                CHECK(answer.body.find("jwt") == std::string::npos);
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("bob joins, then leaves, and asks")
        {
            auto const room_path = "/_matrix/client/v3/rooms/" + fixture.room_id;
            REQUIRE(request(fixture.runtime(), "POST", "/_matrix/client/v3/join/" + fixture.room_id, fixture.bob_token,
                            "{}")
                        .status == 200U);
            auto const joined = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                        token_body(fixture.room_id));
            REQUIRE(request(fixture.runtime(), "POST", room_path + "/leave", fixture.bob_token, "{}").status == 200U);
            auto const left = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                      token_body(fixture.room_id));

            THEN("he had a token while joined and none after")
            {
                CHECK(joined.status == 200U);
                CHECK(left.status == 403U);
                CHECK(errcode_of(left) == "M_FORBIDDEN");
                CHECK(fixture.mock().requests.size() == 1U);
            }
        }

        WHEN("alice names a url that is not this server's SFU")
        {
            auto const other_url = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                           token_body(fixture.room_id, "wss://evil.example.net"));
            auto const prefix_url = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                            token_body(fixture.room_id, "wss://sfu.example.org/"));

            THEN("each is 400 M_INVALID_PARAM, and nothing is fetched or called")
            {
                for (auto const* answer : {&other_url, &prefix_url})
                {
                    CHECK(answer->status == 400U);
                    CHECK(errcode_of(*answer) == "M_INVALID_PARAM");
                }
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("alice names another server, which has no member in the room")
        {
            auto const other_server =
                request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                        R"({"url":"wss://sfu.other.example.net","room_id":")" + fixture.room_id +
                            R"(","slot_id":"m.call#room","member_id":"m","server_name":"other.example.net"})");

            THEN("it is 403 M_FORBIDDEN, nothing is relayed, and LiveKit is not called")
            {
                CHECK(other_server.status == 403U);
                CHECK(errcode_of(other_server) == "M_FORBIDDEN");
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("bob, not joined, names another server")
        {
            auto const answer =
                request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                        R"({"url":"wss://sfu.other.example.net","room_id":")" + fixture.room_id +
                            R"(","slot_id":"m.call#room","member_id":"m","server_name":"other.example.net"})");

            THEN("he gets the not-joined 403 before any relay is considered")
            {
                auto const local = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                           token_body(fixture.room_id));
                CHECK(answer.status == 403U);
                CHECK(answer.body == local.body);
            }
        }
    }
}

SCENARIO("A get_token body is read strictly", "[homeserver][livekit][rtc][negative]")
{
    GIVEN("alice in a room")
    {
        auto fixture = LiveKitFixture{};
        auto const room = fixture.room_id;
        struct Case final
        {
            std::string body;
            std::string errcode;
        };
        auto const long_slot = std::string(256U, 's');
        auto const cases = std::vector<Case>{
            {"[]",                                                                                              "M_BAD_JSON"     },
            {"\"text\"",                                                                                        "M_BAD_JSON"     },
            {R"({"room_id":")" + room + R"(","slot_id":"s","member_id":"m"})",                                  "M_MISSING_PARAM"},
            {R"({"url":"wss://sfu.example.org","slot_id":"s","member_id":"m"})",                                "M_MISSING_PARAM"},
            {R"({"url":"wss://sfu.example.org","room_id":")" + room + R"(","member_id":"m"})",                  "M_MISSING_PARAM"},
            {R"({"url":"wss://sfu.example.org","room_id":")" + room + R"(","slot_id":"s"})",                    "M_MISSING_PARAM"},
            {R"({"url":7,"room_id":")" + room + R"(","slot_id":"s","member_id":"m"})",                          "M_INVALID_PARAM"},
            {R"({"url":"wss://sfu.example.org","room_id":")" + room + R"(","slot_id":"","member_id":"m"})",
             "M_INVALID_PARAM"                                                                                                   },
            {R"({"url":"wss://sfu.example.org","room_id":")" + room + R"(","slot_id":")" + long_slot +
                 R"(","member_id":"m"})",                                                          "M_INVALID_PARAM"},
            {R"({"url":"wss://sfu.example.org","room_id":"#alias:example.org","slot_id":"s","member_id":"m"})",
             "M_INVALID_PARAM"                                                                                                   },
            {R"({"url":"wss://sfu.example.org","room_id":")" + room + R"(","slot_id":"s","member_id":["m"]})",
             "M_INVALID_PARAM"                                                                                                   },
            {R"({"url":"wss://sfu.example.org","room_id":")" + room +
                 R"(","slot_id":"s","member_id":"m","server_name":"not a name"})",                 "M_INVALID_PARAM"},
            {R"({"url":"wss://sfu.example.org","room_id":")" + room +
                 R"(","slot_id":"s","member_id":"m","server_name":5})",                            "M_INVALID_PARAM"},
        };

        WHEN("each malformed body is sent")
        {
            THEN("each is a 400 with its errcode, and LiveKit is never called")
            {
                for (auto const& item : cases)
                {
                    INFO(item.body);
                    auto const answer =
                        request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token, item.body);
                    CHECK(answer.status == 400U);
                    CHECK(errcode_of(answer) == item.errcode);
                }
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("server_name is absent, which asks for this server's SFU")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{unstable_path}, fixture.alice_token,
                                        R"({"url":"wss://sfu.example.org","room_id":")" + room +
                                            R"(","slot_id":"m.call#ROOM","member_id":"m"})");

            THEN("a token is issued for the room the legacy slot shares with m.call#room")
            {
                REQUIRE(answer.status == 200U);
                REQUIRE(fixture.mock().requests.size() == 1U);
                auto const room_name = hs::livekit_room_name(room, "m.call#room");
                REQUIRE(room_name.has_value());
                CHECK(fixture.mock().requests.front().body.find(*room_name) != std::string::npos);
            }
        }
    }
}

SCENARIO("No token is issued when LiveKit, the secret or the outbound budget fails",
         "[homeserver][livekit][rtc][negative]")
{
    GIVEN("alice in a room")
    {
        WHEN("LiveKit cannot be reached, or refuses CreateRoom")
        {
            auto fixture = LiveKitFixture{};
            auto const reachable = GENERATE(false, true);
            fixture.mock().reachable = reachable;
            fixture.mock().status = 401U;
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        token_body(fixture.room_id));

            THEN("the answer is 502 with no token")
            {
                CHECK(answer.status == 502U);
                CHECK(errcode_of(answer) == "M_UNKNOWN");
                CHECK(answer.body.find("jwt") == std::string::npos);
                CHECK(fixture.mock().requests.size() == 1U);
            }
        }

        WHEN("every client outbound slot is taken")
        {
            auto fixture = LiveKitFixture{};
            fixture.runtime().homeserver.client_outbound_proxy_policy.global_cap = 1U;
            auto const held = hs::admit_client_outbound_proxy(fixture.runtime().homeserver, "another-client");
            REQUIRE(held.has_value());
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        token_body(fixture.room_id));

            THEN("the answer is 429 with retry_after_ms, before LiveKit is called")
            {
                CHECK(answer.status == 429U);
                CHECK(errcode_of(answer) == "M_LIMIT_EXCEEDED");
                auto const body = parse_object(answer.body);
                CHECK(int_member(body, "retry_after_ms") != nullptr);
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("the API secret file is missing, or holds a secret shorter than 32 bytes")
        {
            auto const short_secret = SecretFile{"0123456789abcdef0123456789abcde"};
            auto const missing = GENERATE(false, true);
            auto fixture =
                LiveKitFixture{missing ? std::string{"/nonexistent/merovingian-livekit-secret"} : short_secret.path()};
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        token_body(fixture.room_id));

            THEN("the answer is 500 with no token, and LiveKit is never called")
            {
                CHECK(answer.status == 500U);
                CHECK(errcode_of(answer) == "M_UNKNOWN");
                CHECK(answer.body.find("jwt") == std::string::npos);
                CHECK(fixture.mock().requests.empty());
            }
        }
    }
}

SCENARIO("get_token is for active accounts with an access token", "[homeserver][livekit][rtc][negative]")
{
    GIVEN("alice in a room")
    {
        auto fixture = LiveKitFixture{};

        WHEN("the request has no access token")
        {
            auto const answer =
                request(fixture.runtime(), "POST", std::string{stable_path}, {}, token_body(fixture.room_id));

            THEN("it is 401 M_MISSING_TOKEN")
            {
                CHECK(answer.status == 401U);
                CHECK(errcode_of(answer) == "M_MISSING_TOKEN");
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("alice is suspended, or locked")
        {
            auto const locked = GENERATE(false, true);
            auto& homeserver = fixture.runtime().homeserver;
            REQUIRE(hs::bootstrap_admin_user(homeserver, "admin", std::string{password}).ok);
            REQUIRE(hs::set_local_user_moderation(homeserver, "@admin:example.org", "@alice:example.org", !locked,
                                                  locked, "t", "t")
                        .ok);
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        token_body(fixture.room_id));

            THEN("the moderation gate refuses it and no token is issued")
            {
                CHECK(answer.status == (locked ? 401U : 403U));
                CHECK(errcode_of(answer) == (locked ? "M_USER_LOCKED" : "M_USER_SUSPENDED"));
                CHECK(fixture.mock().requests.empty());
            }
        }
    }
}

SCENARIO("The routes, /versions and the transports say the same thing", "[homeserver][livekit][rtc][client-server]")
{
    GIVEN("a server with the built-in service")
    {
        auto fixture = LiveKitFixture{};

        WHEN("a client reads /versions and both transport routes")
        {
            auto const versions = request(fixture.runtime(), "GET", "/_matrix/client/versions", {}, {});
            auto const stable =
                request(fixture.runtime(), "GET", "/_matrix/client/v1/rtc/transports", fixture.alice_token, {});
            auto const unstable =
                request(fixture.runtime(), "GET", "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
                        fixture.alice_token, {});

            THEN("both MSC4195 flags are true and the SFU is advertised by its url")
            {
                REQUIRE(versions.status == 200U);
                auto const body = parse_object(versions.body);
                auto const* features = object_member_as_object(body, "unstable_features");
                REQUIRE(features != nullptr);
                auto const* flag = bool_member(*features, "org.matrix.msc4195");
                auto const* stable_flag = bool_member(*features, "org.matrix.msc4195.stable");
                REQUIRE((flag != nullptr && stable_flag != nullptr));
                CHECK((*flag && *stable_flag));
                CHECK(stable.status == 200U);
                CHECK(stable.body == R"({"transports":[{"type":"livekit","url":"wss://sfu.example.org"},)"
                                     R"({"type":"m.livekit","url":"wss://sfu.example.org"}]})");
                CHECK(unstable.status == 200U);
                CHECK(unstable.body == R"({"rtc_transports":[{"type":"livekit","url":"wss://sfu.example.org"}]})");
            }
        }
    }

    GIVEN("a server without it")
    {
        auto started = hs::start_client_server(livekit_config({}));
        REQUIRE(started.started);
        auto const mock = std::make_shared<MockLiveKit>();
        install_mock(started.runtime, mock);
        auto const token = login(started.runtime, "alice");

        WHEN("a client asks for a token on either path, and reads /versions")
        {
            auto const versions = request(started.runtime, "GET", "/_matrix/client/versions", {}, {});

            THEN("each path is 404 M_UNRECOGNIZED and both flags are false")
            {
                for (auto const path : {stable_path, unstable_path})
                {
                    auto const answer =
                        request(started.runtime, "POST", std::string{path}, token, token_body("!room:example.org"));
                    CHECK(answer.status == 404U);
                    CHECK(errcode_of(answer) == "M_UNRECOGNIZED");
                }
                REQUIRE(versions.status == 200U);
                auto const body = parse_object(versions.body);
                auto const* features = object_member_as_object(body, "unstable_features");
                REQUIRE(features != nullptr);
                auto const* flag = bool_member(*features, "org.matrix.msc4195");
                auto const* stable_flag = bool_member(*features, "org.matrix.msc4195.stable");
                REQUIRE((flag != nullptr && stable_flag != nullptr));
                CHECK_FALSE(*flag);
                CHECK_FALSE(*stable_flag);
                CHECK(mock->requests.empty());
            }
        }
    }
}

SCENARIO("The livekit log names the user and room and never the token, the secret or the member",
         "[homeserver][livekit][rtc][logging]")
{
    GIVEN("alice in a room")
    {
        auto fixture = LiveKitFixture{};

        WHEN("a token is issued and one refused, with the log captured")
        {
            auto const capture = ConsoleLogCapture{};
            auto const issued = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        token_body(fixture.room_id, sfu_url, "SECRETDEVICE_member"));
            auto const refused = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.bob_token,
                                         token_body(fixture.room_id, sfu_url, "SECRETDEVICE_member"));
            auto const text = capture.text();

            THEN("the events are there, with no jwt, secret or member ID")
            {
                REQUIRE(issued.status == 200U);
                REQUIRE(refused.status == 403U);
                auto const body = parse_object(issued.body);
                auto const* jwt = string_member(body, "jwt");
                REQUIRE(jwt != nullptr);
                CHECK(text.find("livekit.token.issued") != std::string::npos);
                CHECK(text.find("livekit.token.refused") != std::string::npos);
                CHECK(text.find(*jwt) == std::string::npos);
                CHECK(text.find(api_secret) == std::string::npos);
                CHECK(text.find("SECRETDEVICE") == std::string::npos);
                CHECK(text.find("m.call#room") == std::string::npos);
            }
        }
    }
}

SCENARIO("A federated request gets a subscribe-only token for a user of the origin joined here",
         "[homeserver][livekit][rtc][federation]")
{
    GIVEN("alice's room, which carol of remote.example.org has joined")
    {
        auto fixture = LiveKitFixture{};
        seed_remote_join(fixture.runtime(), fixture.room_id, carol);

        WHEN("remote.example.org asks for a token for carol")
        {
            auto const answer = federated(fixture.runtime(), remote_server, federation_body(fixture.room_id, carol));

            THEN("the token is carol's, for the MSC4195 names, and may subscribe but not publish")
            {
                REQUIRE(answer.ok);
                REQUIRE(answer.status == 200U);
                auto const body = parse_object(answer.value);
                REQUIRE(body.size() == 1U);
                auto const* jwt = string_member(body, "jwt");
                REQUIRE(jwt != nullptr);
                auto const payload = verified_payload(*jwt);
                auto const identity = hs::livekit_participant_identity(carol, "DEVICEID_member");
                auto const room_name = hs::livekit_room_name(fixture.room_id, "m.call#room");
                REQUIRE((identity.has_value() && room_name.has_value()));
                auto const* sub = string_member(payload, "sub");
                REQUIRE(sub != nullptr);
                CHECK(*sub == *identity);
                auto const* video = object_member_as_object(payload, "video");
                REQUIRE(video != nullptr);
                auto const* room = string_member(*video, "room");
                REQUIRE(room != nullptr);
                CHECK(*room == *room_name);
                auto const* join = bool_member(*video, "roomJoin");
                auto const* publish = bool_member(*video, "canPublish");
                auto const* publish_data = bool_member(*video, "canPublishData");
                auto const* subscribe = bool_member(*video, "canSubscribe");
                REQUIRE((join != nullptr && publish != nullptr && publish_data != nullptr && subscribe != nullptr));
                CHECK(*join);
                CHECK(*subscribe);
                // Written as false, never left out: LiveKit reads an absent canPublish as true (ADR-0828).
                CHECK_FALSE(*publish);
                CHECK_FALSE(*publish_data);
                CHECK(video->size() == 5U);
                CHECK(answer.value.find("carol") == std::string::npos);
            }

            THEN("LiveKit is not called on another server's behalf")
            {
                CHECK(fixture.mock().requests.empty());
            }
        }
    }
}

SCENARIO("A federated request is refused unless this server's own state shows the user of the origin joined",
         "[homeserver][livekit][rtc][federation][negative]")
{
    GIVEN("alice's room, which carol of remote.example.org has joined")
    {
        auto fixture = LiveKitFixture{};
        seed_remote_join(fixture.runtime(), fixture.room_id, carol);
        auto const joined = federated(fixture.runtime(), remote_server, federation_body(fixture.room_id, carol));
        REQUIRE(joined.status == 200U);

        WHEN("the user is not of the origin, is not joined, or the room is not one this server is in")
        {
            auto const other_origin =
                federated(fixture.runtime(), "other.example.net", federation_body(fixture.room_id, carol));
            auto const not_joined = federated(fixture.runtime(), remote_server,
                                              federation_body(fixture.room_id, "@dave:remote.example.org"));
            auto const no_room =
                federated(fixture.runtime(), remote_server, federation_body("!nosuchroom:example.org", carol));

            THEN("each is one and the same 403 M_FORBIDDEN, and nothing is signed or called")
            {
                for (auto const* refused : {&other_origin, &not_joined, &no_room})
                {
                    CHECK_FALSE(refused->ok);
                    CHECK(refused->status == 403U);
                    CHECK(refused->errcode == "M_FORBIDDEN");
                    CHECK(refused->reason == other_origin.reason);
                    CHECK(refused->value.find("jwt") == std::string::npos);
                }
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("the room's server ACL denies remote.example.org, though carol is still joined")
        {
            seed_server_acl(fixture.runtime(), fixture.room_id, remote_server);
            auto const denied = federated(fixture.runtime(), remote_server, federation_body(fixture.room_id, carol));
            auto const unknown_origin =
                federated(fixture.runtime(), "other.example.net", federation_body(fixture.room_id, carol));

            THEN("it is the same 403 M_FORBIDDEN, and nothing is signed or called")
            {
                CHECK(denied.status == 403U);
                CHECK(denied.errcode == "M_FORBIDDEN");
                CHECK(denied.reason == unknown_origin.reason);
                CHECK(denied.value.find("jwt") == std::string::npos);
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("carol leaves")
        {
            auto& store = fixture.runtime().homeserver.database.persistent_store;
            auto const leave_id = std::string{"$leave-of-carol"};
            store.events.push_back({leave_id,
                                    fixture.room_id,
                                    std::string{carol},
                                    R"({"content":{"membership":"leave"},"type":"m.room.member"})",
                                    10U,
                                    0U,
                                    {},
                                    {},
                                    {}});
            for (auto& row : store.state)
            {
                if (row.room_id == fixture.room_id && row.event_type == "m.room.member" && row.state_key == carol)
                {
                    row.event_id = leave_id;
                }
            }
            auto const left = federated(fixture.runtime(), remote_server, federation_body(fixture.room_id, carol));

            THEN("she is refused like a user never joined")
            {
                CHECK(left.status == 403U);
                CHECK(left.errcode == "M_FORBIDDEN");
            }
        }

        WHEN("the url is not this server's SFU, or the body is malformed")
        {
            auto const wrong_url = federated(fixture.runtime(), remote_server,
                                             federation_body(fixture.room_id, carol, "wss://sfu.remote.example.org"));
            auto const other_server_name = federated(
                fixture.runtime(), remote_server,
                R"({"url":"wss://sfu.example.org","room_id":")" + fixture.room_id +
                    R"(","slot_id":"m.call#room","member_id":"m","user_id":"@carol:remote.example.org","server_name":"remote.example.org"})");
            auto const no_user = federated(fixture.runtime(), remote_server,
                                           R"({"url":"wss://sfu.example.org","room_id":")" + fixture.room_id +
                                               R"(","slot_id":"m.call#room","member_id":"m"})");
            auto const bad_user =
                federated(fixture.runtime(), remote_server, federation_body(fixture.room_id, "carol"));
            auto const not_json = federated(fixture.runtime(), remote_server, "[]");

            THEN("each is a 400, and no token is issued")
            {
                CHECK(wrong_url.status == 400U);
                CHECK(wrong_url.errcode == "M_INVALID_PARAM");
                for (auto const* refused : {&other_server_name, &no_user, &bad_user, &not_json})
                {
                    CHECK(refused->status == 400U);
                    CHECK(refused->value.find("jwt") == std::string::npos);
                }
                CHECK(fixture.mock().requests.empty());
            }
        }
    }

    GIVEN("a server with no token service")
    {
        auto started = hs::start_client_server(livekit_config({}));
        REQUIRE(started.started);

        WHEN("a federated request arrives")
        {
            auto const answer = federated(started.runtime, remote_server, federation_body("!room:example.org", carol));

            THEN("it is 404 M_UNRECOGNIZED")
            {
                CHECK(answer.status == 404U);
                CHECK(answer.errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("A token for another server's SFU is relayed to that server, and only its jwt is passed on",
         "[homeserver][livekit][rtc][federation][relay]")
{
    GIVEN("alice's room, which carol of remote.example.org has joined, and remote.example.org issuing a token")
    {
        auto fixture = LiveKitFixture{};
        seed_remote_join(fixture.runtime(), fixture.room_id, carol);
        auto remote = RemoteTokenServer{fixture.runtime(),
                                        tls_mock::json_http_response("200 OK", R"({"jwt":"aGVhZA.Ym9keQ.c2ln"})")};

        WHEN("alice asks for a token for remote.example.org's SFU")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        relay_body(fixture.room_id));
            auto const& seen = remote.finish();

            THEN("she gets the other server's jwt and nothing else")
            {
                REQUIRE(answer.status == 200U);
                auto const body = parse_object(answer.body);
                REQUIRE(body.size() == 1U);
                auto const* jwt = string_member(body, "jwt");
                REQUIRE(jwt != nullptr);
                CHECK(*jwt == "aGVhZA.Ym9keQ.c2ln");
            }

            THEN("the request went signed to the stable federation path, naming alice and no server_name")
            {
                CHECK(seen.starts_with("POST /_matrix/federation/v1/rtc/livekit/get_token HTTP/1.1\r\n"));
                CHECK(seen.find("X-Matrix origin=\"example.org\"") != std::string::npos);
                auto const body_start = seen.find("\r\n\r\n");
                REQUIRE(body_start != std::string::npos);
                CHECK(
                    seen.substr(body_start + 4U) ==
                    R"({"member_id":"DEVICEID_member","room_id":")" + fixture.room_id +
                        R"(","slot_id":"m.call#room","url":"wss://sfu.remote.example.org","user_id":"@alice:example.org"})");
                CHECK(fixture.mock().requests.empty());
            }
        }
    }

    GIVEN("alice's room, which carol of remote.example.org has joined, and a server ACL denying remote.example.org")
    {
        auto fixture = LiveKitFixture{};
        seed_remote_join(fixture.runtime(), fixture.room_id, carol);
        seed_server_acl(fixture.runtime(), fixture.room_id, remote_server);

        WHEN("alice asks for a token for remote.example.org's SFU")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        relay_body(fixture.room_id));

            THEN("it is 403 M_FORBIDDEN without a request to that server, as for a server not in the room")
            {
                CHECK(answer.status == 403U);
                CHECK(errcode_of(answer) == "M_FORBIDDEN");
                CHECK(fixture.mock().requests.empty());
            }
        }
    }

    GIVEN("remote.example.org answering get_token with a refusal, an error or a malformed jwt")
    {
        struct Case final
        {
            std::string response;
            std::uint16_t status;
            std::string errcode;
        };
        auto const scenario = GENERATE(
            Case{tls_mock::json_http_response("403 Forbidden",
                                              R"({"errcode":"M_FORBIDDEN","error":"room secret-detail"})"),
                 403U, "M_FORBIDDEN"},
            Case{tls_mock::json_http_response("400 Bad Request",
                                              R"({"errcode":"M_INVALID_PARAM","error":"url secret-detail"})"),
                 400U, "M_INVALID_PARAM"},
            Case{tls_mock::json_http_response("403 Forbidden", R"({"errcode":"M_LIMIT_EXCEEDED","error":"x"})"), 502U,
                 "M_UNKNOWN"},
            Case{tls_mock::json_http_response("404 Not Found", R"({"errcode":"M_UNRECOGNIZED","error":"x"})"), 502U,
                 "M_UNKNOWN"},
            Case{tls_mock::json_http_response("500 Internal Server Error", R"({"errcode":"M_UNKNOWN","error":"x"})"),
                 502U, "M_UNKNOWN"},
            Case{tls_mock::json_http_response("200 OK", R"({"jwt":"not a token"})"), 502U, "M_UNKNOWN"},
            Case{tls_mock::json_http_response("200 OK", R"({"jwt":"a..c"})"), 502U, "M_UNKNOWN"},
            Case{tls_mock::json_http_response("200 OK", R"({"token":"aGVhZA.Ym9keQ.c2ln"})"), 502U, "M_UNKNOWN"});
        auto fixture = LiveKitFixture{};
        seed_remote_join(fixture.runtime(), fixture.room_id, carol);
        auto remote = RemoteTokenServer{fixture.runtime(), scenario.response};

        WHEN("alice asks for a token for its SFU")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{stable_path}, fixture.alice_token,
                                        relay_body(fixture.room_id));
            std::ignore = remote.finish();

            THEN("403 and 400 are passed on in this server's words, and anything else is 502 M_UNKNOWN")
            {
                CHECK(answer.status == scenario.status);
                CHECK(errcode_of(answer) == scenario.errcode);
                CHECK(answer.body.find("secret-detail") == std::string::npos);
                CHECK(answer.body.find("jwt") == std::string::npos);
                CHECK(fixture.runtime().homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}
