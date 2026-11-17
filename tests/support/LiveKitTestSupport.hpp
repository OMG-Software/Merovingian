// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// A server with the built-in LiveKit token service on (ADR-0829), a stand-in for LiveKit's room service, and the
// request helpers the LiveKit flow tests share. LiveKit is never reached over the network.

#include "InMemoryDatabaseConfig.hpp"
#include "JsonTestSupport.hpp"
#include "MasterKey.hpp"
#include "RegistrationToken.hpp"
#include "TempDirectory.hpp"
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
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace merovingian::tests::livekit
{

inline constexpr auto sfu_url = std::string_view{"wss://sfu.example.org"};
inline constexpr auto api_url = std::string_view{"https://sfu-api.example.org"};
inline constexpr auto api_key = std::string_view{"APIkey_test"};
// 32 bytes, the minimum the signers accept.
inline constexpr auto api_secret = std::string_view{"0123456789abcdef0123456789abcdef"};
inline constexpr auto stable_path = std::string_view{"/_matrix/client/v1/rtc/livekit/get_token"};
inline constexpr auto unstable_path =
    std::string_view{"/_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token"};
inline constexpr auto password = std::string_view{"CorrectHorse7!"};

[[nodiscard]] inline auto secret_bytes(std::string_view const text) -> std::vector<std::uint8_t>
{
    return {text.begin(), text.end()};
}

class SecretFile final
{
public:
    explicit SecretFile(std::string_view const contents)
        : m_directory{temporary_directory() / ("merovingian-livekit-" + std::to_string(std::random_device{}()))}
    {
        std::filesystem::create_directories(m_directory);
        std::filesystem::permissions(m_directory, std::filesystem::perms::owner_all);
        m_path = m_directory / "livekit_secret";
        auto stream = std::ofstream{m_path, std::ios::binary};
        stream << contents;
        stream.close();
        std::filesystem::permissions(m_path, std::filesystem::perms::owner_read);
    }
    ~SecretFile()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(m_directory, ignored);
    }
    SecretFile(SecretFile const&) = delete;
    auto operator=(SecretFile const&) -> SecretFile& = delete;
    SecretFile(SecretFile&&) = delete;
    auto operator=(SecretFile&&) -> SecretFile& = delete;

    [[nodiscard]] auto path() const -> std::string
    {
        return m_path.string();
    }

private:
    std::filesystem::path m_directory;
    std::filesystem::path m_path;
};

// The configuration with the built-in service on when `secret_path` is set, off when it is empty.
[[nodiscard]] inline auto livekit_config(std::string const& secret_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    if (!secret_path.empty())
    {
        server.rtc.token_service.url = std::string{sfu_url};
        server.rtc.token_service.api_url = std::string{api_url};
        server.rtc.token_service.api_key = std::string{api_key};
        server.rtc.token_service.api_secret_file = secret_path;
        server.rtc.token_service.token_lifetime_seconds = 600U;
    }
    return {
        std::move(server),   merovingian::config::ListenersConfig{},        in_memory_database_config(),
        std::move(security), merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

struct Answer final
{
    std::uint16_t status{};
    std::string body{};
};

[[nodiscard]] inline auto request(homeserver::ClientServerRuntime& runtime, std::string method, std::string target,
                                  std::string token, std::string body) -> Answer
{
    auto const result = homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), std::move(token), std::move(body)});
    return {result.response.status, result.response.body};
}

[[nodiscard]] inline auto errcode_of(Answer const& answer) -> std::string
{
    auto const body = parse_object(answer.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] inline auto login(homeserver::ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    REQUIRE(
        request(runtime, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, std::string{password}))
            .status == 200U);
    auto const response =
        request(runtime, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                    R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":"D1"})");
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] inline auto token_body(std::string_view const room_id, std::string_view const url = sfu_url,
                                     std::string_view const member_id = "DEVICEID_member") -> std::string
{
    return R"({"url":")" + std::string{url} + R"(","room_id":")" + std::string{room_id} +
           R"(","slot_id":"m.call#room","member_id":")" + std::string{member_id} + R"(","server_name":"example.org"})";
}

// LiveKit, as far as the room service goes: records each request and answers `GetParticipant` with
// `get_participant_status` and `get_participant_body`, any other call with `status` and `{}`, or fails the call.
struct MockLiveKit final
{
    std::vector<merovingian::http::OutboundRequest> requests{};
    std::uint16_t status{200U};
    std::uint16_t get_participant_status{500U};
    std::string get_participant_body{"{}"};
    bool reachable{true};
};

inline auto install_mock(homeserver::ClientServerRuntime& runtime, std::shared_ptr<MockLiveKit> const& mock) -> void
{
    runtime.homeserver.test_livekit_perform = [mock](merovingian::http::OutboundRequest const& outbound) {
        mock->requests.push_back(outbound);
        auto result = merovingian::http::OutboundResult{};
        result.ok = mock->reachable;
        if (mock->reachable)
        {
            auto const get_participant = outbound.url.ends_with("/twirp/livekit.RoomService/GetParticipant");
            result.response.status = get_participant ? mock->get_participant_status : mock->status;
            result.response.body = get_participant ? mock->get_participant_body : std::string{"{}"};
        }
        else
        {
            result.error = merovingian::http::OutboundError::network_error;
            result.error_detail = "connection refused";
        }
        return result;
    };
}

[[nodiscard]] inline auto header_value(merovingian::http::OutboundRequest const& outbound, std::string_view const name)
    -> std::optional<std::string>
{
    for (auto const& header : outbound.headers)
    {
        if (header.name == name)
        {
            return header.value;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto verified_payload(std::string_view const token) -> merovingian::canonicaljson::Object
{
    auto const secret = secret_bytes(api_secret);
    auto const verified = merovingian::crypto::verify_hs256_token(token, std::span<std::uint8_t const>{secret});
    REQUIRE(verified.has_value());
    CHECK(verified->header_json == R"({"alg":"HS256","typ":"JWT"})");
    return parse_object(verified->payload_json);
}

// A server with the service on, alice in a public room and bob registered but not in it.
class LiveKitFixture final
{
public:
    explicit LiveKitFixture(std::string const& secret_path = {})
        : m_secret{api_secret}
        , m_started{homeserver::start_client_server(
              livekit_config(secret_path.empty() ? m_secret.path() : secret_path))}
        , m_mock{std::make_shared<MockLiveKit>()}
    {
        REQUIRE(m_started.started);
        install_mock(runtime(), m_mock);
        alice_token = login(runtime(), "alice");
        bob_token = login(runtime(), "bob");
        auto const created =
            request(runtime(), "POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const body = parse_object(created.body);
        auto const* id = string_member(body, "room_id");
        REQUIRE(id != nullptr);
        room_id = *id;
    }

    [[nodiscard]] auto runtime() -> homeserver::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto mock() const -> MockLiveKit&
    {
        return *m_mock;
    }

    std::string alice_token{};
    std::string bob_token{};
    std::string room_id{};

private:
    SecretFile m_secret;
    homeserver::ClientServerStartResult m_started;
    std::shared_ptr<MockLiveKit> m_mock;
};

} // namespace merovingian::tests::livekit
