// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSC4195 (MatrixRTC transport using LiveKit backend; unstable, not part of v1.19), the client get_token endpoint, at
// the revision this server implements:
// https://github.com/matrix-org/matrix-spec-proposals/blob/6d49798949e1b31023565d4ff1c7fe10f4cacf83/proposals/4195-matrixrtc-livekit.md
// LiveKit is HomeserverRuntime::test_livekit_perform; what this server decides beyond the MSC is in
// tests/integration/test_livekit_token_flow.cpp.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/crypto/VerifiedHs256Token.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
using namespace merovingian::tests;

constexpr auto sfu_url = std::string_view{"wss://livekit.example.org"};
constexpr auto secret = std::string_view{"conformance-secret-of-32-bytes!!"};
constexpr auto path = std::string_view{"/_matrix/client/v1/rtc/livekit/get_token"};

class SecretDirectory final
{
public:
    SecretDirectory()
        : m_directory{temporary_directory() / ("merovingian-msc4195-" + std::to_string(std::random_device{}()))}
    {
        std::filesystem::create_directories(m_directory);
        std::filesystem::permissions(m_directory, std::filesystem::perms::owner_all);
        auto stream = std::ofstream{file(), std::ios::binary};
        stream << secret;
        stream.close();
        std::filesystem::permissions(file(), std::filesystem::perms::owner_read);
    }
    ~SecretDirectory()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(m_directory, ignored);
    }
    SecretDirectory(SecretDirectory const&) = delete;
    auto operator=(SecretDirectory const&) -> SecretDirectory& = delete;
    SecretDirectory(SecretDirectory&&) = delete;
    auto operator=(SecretDirectory&&) -> SecretDirectory& = delete;

    [[nodiscard]] auto file() const -> std::filesystem::path
    {
        return m_directory / "livekit_secret";
    }

private:
    std::filesystem::path m_directory;
};

struct Reply final
{
    std::uint16_t status{};
    std::string body{};
};

[[nodiscard]] auto call(hs::ClientServerRuntime& runtime, std::string method, std::string target, std::string token,
                        std::string body) -> Reply
{
    auto const result = hs::handle_client_server_request(
        runtime, {std::move(method), std::move(target), std::move(token), std::move(body)});
    return {result.response.status, result.response.body};
}

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto login(hs::ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    REQUIRE(call(runtime, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const reply = call(runtime, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                                R"(:example.org"},"password":"CorrectHorse7!","device_id":"D1"})");
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto request_body(std::string const& room_id, std::string_view const url = sfu_url) -> std::string
{
    return R"({"server_name":"example.org","url":")" + std::string{url} + R"(","room_id":")" + room_id +
           R"(","slot_id":"m.call#room","member_id":"xyzABCDEF10123"})";
}

[[nodiscard]] auto now_seconds() -> std::int64_t
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A server issuing tokens for its own SFU, alice in a public room and bob in none.
class Msc4195Server final
{
public:
    Msc4195Server()
        : m_started{hs::start_client_server(config())}
        , m_calls{std::make_shared<std::vector<merovingian::http::OutboundRequest>>()}
    {
        REQUIRE(m_started.started);
        auto calls = m_calls;
        runtime().homeserver.test_livekit_perform = [calls](merovingian::http::OutboundRequest const& outbound) {
            calls->push_back(outbound);
            auto result = merovingian::http::OutboundResult{};
            result.ok = true;
            result.response.status = 200U;
            result.response.body = "{}";
            return result;
        };
        alice = login(runtime(), "alice");
        bob = login(runtime(), "bob");
        auto const created =
            call(runtime(), "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const body = parse_object(created.body);
        auto const* id = string_member(body, "room_id");
        REQUIRE(id != nullptr);
        room_id = *id;
    }

    [[nodiscard]] auto runtime() -> hs::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto livekit_calls() const -> std::vector<merovingian::http::OutboundRequest> const&
    {
        return *m_calls;
    }

    std::string alice{};
    std::string bob{};
    std::string room_id{};

private:
    [[nodiscard]] auto config() const -> merovingian::config::Config
    {
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = shared_master_key_file();
        enable_token_registration(security);
        auto server = merovingian::config::ServerConfig{};
        server.rtc.token_service.url = std::string{sfu_url};
        server.rtc.token_service.api_url = "https://livekit-api.example.org";
        server.rtc.token_service.api_key = "APIconformance";
        server.rtc.token_service.api_secret_file = m_secret.file().string();
        return {
            std::move(server),   merovingian::config::ListenersConfig{},        in_memory_database_config(),
            std::move(security), merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
    }

    SecretDirectory m_secret{};
    hs::ClientServerStartResult m_started;
    using CallLog = std::vector<merovingian::http::OutboundRequest>;
    std::shared_ptr<CallLog> m_calls; // SHARED_PTR: reviewed — the call log is shared with the installed hook
};

} // namespace

// Spec: MSC4195 (unstable; not part of v1.19)
// Endpoint / Section: POST /_matrix/client/v1/rtc/livekit/get_token
// URL: proposals/4195-matrixrtc-livekit.md, "The receiving server MUST reject the request in all of the following
//      cases", and "Validation or authorisation failures MUST NOT reveal information about whether a particular Matrix
//      user, device, or room exists."
//
// A user not joined to `room_id` is refused with 403 M_FORBIDDEN, and a room that does not exist is answered alike.
SCENARIO("get_token refuses a user not joined to the room, revealing nothing", "[conformance][client-server][livekit]")
{
    GIVEN("alice's room, and bob in none")
    {
        auto server = Msc4195Server{};

        WHEN("bob asks for a token for alice's room, and for a room that does not exist")
        {
            auto const existing =
                call(server.runtime(), "POST", std::string{path}, server.bob, request_body(server.room_id));
            auto const missing = call(server.runtime(), "POST", std::string{path}, server.bob,
                                      request_body("!doesnotexist:example.org"));

            THEN("both are 403 M_FORBIDDEN with the same body")
            {
                // Spec MUST: a requesting user not joined to the room is rejected with HTTP 403 / M_FORBIDDEN.
                REQUIRE(existing.status == 403U);
                REQUIRE(errcode_of(existing) == "M_FORBIDDEN");
                // Spec MUST NOT: reveal whether a particular room exists.
                REQUIRE(missing.status == existing.status);
                REQUIRE(missing.body == existing.body);
            }
        }
    }
}

// Spec: MSC4195 (unstable; not part of v1.19)
// Endpoint / Section: POST /_matrix/client/v1/rtc/livekit/get_token
// URL: proposals/4195-matrixrtc-livekit.md, "If `server_name` is the server's own name and `url` does not match one of
//      the server's own SFUs, reject the request with HTTP 400 / `M_INVALID_PARAM`."
SCENARIO("get_token refuses a url that is not one of this server's SFUs", "[conformance][client-server][livekit]")
{
    GIVEN("alice, joined to her room")
    {
        auto server = Msc4195Server{};

        WHEN("she names this server and another SFU")
        {
            auto const reply = call(server.runtime(), "POST", std::string{path}, server.alice,
                                    request_body(server.room_id, "wss://other-sfu.example.net"));

            THEN("the answer is 400 M_INVALID_PARAM")
            {
                // Spec MUST: `url` not one of the server's own SFUs is HTTP 400 / M_INVALID_PARAM.
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
                REQUIRE(server.livekit_calls().empty());
            }
        }
    }
}

// Spec: MSC4195 (unstable; not part of v1.19)
// Endpoint / Section: POST /_matrix/client/v1/rtc/livekit/get_token; "Access token properties"; "LiveKit room name
//      and participant identity"
// URL: proposals/4195-matrixrtc-livekit.md
//
// For its own server the server "ensures that the room exists, creating it if needed" (REQUIRED), then answers 200
// with a single required property `jwt`. The token's `sub` MUST be the participant identity, `nbf` MUST be the current
// time, `video.room` MUST be the room name, `roomCreate` and `hidden` MUST be false, and `roomJoin`, `canPublish` (a
// local user) and `canSubscribe` MUST be true.
SCENARIO("get_token creates the LiveKit room and answers a token with the MSC4195 claims",
         "[conformance][client-server][livekit]")
{
    GIVEN("alice, joined to her room")
    {
        auto server = Msc4195Server{};

        WHEN("she asks for a token for this server's SFU")
        {
            auto const before = now_seconds();
            auto const reply =
                call(server.runtime(), "POST", std::string{path}, server.alice, request_body(server.room_id));
            auto const after = now_seconds();

            THEN("the room was created first and the token carries exactly what the MSC requires")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* jwt = string_member(body, "jwt");
                // Spec: a JSON object with a single required property `jwt`.
                REQUIRE(jwt != nullptr);
                auto const room_name = hs::livekit_room_name(server.room_id, "m.call#room");
                auto const identity = hs::livekit_participant_identity("@alice:example.org", "xyzABCDEF10123");
                REQUIRE((room_name.has_value() && identity.has_value()));
                // Spec REQUIRED: the server ensures the room exists before answering.
                REQUIRE(server.livekit_calls().size() == 1U);
                REQUIRE(server.livekit_calls().front().url.ends_with("/twirp/livekit.RoomService/CreateRoom"));
                REQUIRE(server.livekit_calls().front().body.find(*room_name) != std::string::npos);

                auto const key = std::vector<std::uint8_t>{secret.begin(), secret.end()};
                auto const verified = merovingian::crypto::verify_hs256_token(*jwt, std::span<std::uint8_t const>{key});
                REQUIRE(verified.has_value());
                auto const payload = parse_object(verified->payload_json);
                auto const* sub = string_member(payload, "sub");
                // Spec MUST: `sub` is the LiveKit participant identity.
                REQUIRE(sub != nullptr);
                REQUIRE(*sub == *identity);
                auto const* nbf = int_member(payload, "nbf");
                // Spec MUST: `nbf` is the current time.
                REQUIRE(nbf != nullptr);
                REQUIRE(*nbf >= before);
                REQUIRE(*nbf <= after);
                auto const* video = object_member_as_object(payload, "video");
                REQUIRE(video != nullptr);
                auto const* room = string_member(*video, "room");
                // Spec MUST: `video.room` is the LiveKit room name.
                REQUIRE(room != nullptr);
                REQUIRE(*room == *room_name);
                // Spec MUST: `video.roomCreate` and `video.hidden` are false (LiveKit reads an absent grant as false).
                auto const* create = bool_member(*video, "roomCreate");
                auto const* hidden = bool_member(*video, "hidden");
                REQUIRE((create == nullptr || !*create));
                REQUIRE((hidden == nullptr || !*hidden));
                REQUIRE(object_member(*video, "roomAdmin") == nullptr);
                // Spec MUST: `roomJoin`, `canPublish` for a local user and `canSubscribe` are true. Written explicitly:
                // LiveKit reads an absent `canPublish` or `canSubscribe` as true too, but the claim says so itself.
                auto const* join = bool_member(*video, "roomJoin");
                auto const* publish = bool_member(*video, "canPublish");
                auto const* subscribe = bool_member(*video, "canSubscribe");
                REQUIRE((join != nullptr && publish != nullptr && subscribe != nullptr));
                REQUIRE((*join && *publish && *subscribe));
            }
        }
    }
}
