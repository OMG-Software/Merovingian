// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// IPC channel unit tests — exercises the encrypted framing and request/response
// protocol using a real AF_UNIX socketpair (no mocking).
//
// Spec: the IPC channel is an internal transport layer with no Matrix spec
// counterpart. Tests focus on correctness of the encryption handshake, frame
// delivery, request/response pairing, and graceful shutdown.

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/ipc_ed25519_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <sodium.h>
#include <sys/socket.h>

namespace
{

struct SocketPair final
{
    merovingian::core::FileDescriptor server_fd{};
    merovingian::core::FileDescriptor client_fd{};
};

[[nodiscard]] auto make_socketpair() -> SocketPair
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
    return {merovingian::core::FileDescriptor{fds[0]}, merovingian::core::FileDescriptor{fds[1]}};
}

// Constructs a server and client IpcChannel concurrently (required because the
// constructor performs a blocking key exchange handshake — sequential construction
// deadlocks).
struct ChannelPair final
{
    std::unique_ptr<merovingian::ipc::IpcChannel> server{};
    std::unique_ptr<merovingian::ipc::IpcChannel> client{};
};

// Extract a JSON string value for `key`. Returns empty on failure.
[[nodiscard]] auto json_get_str(std::string_view json, std::string_view key) -> std::string
{
    auto const search = std::string{"\""} + std::string{key} + "\":\"";
    auto const pos = json.find(search);
    if (pos == std::string_view::npos)
    {
        return {};
    }
    auto i = pos + search.size();
    auto result = std::string{};
    while (i < json.size())
    {
        auto const ch = json[i];
        if (ch == '\"')
        {
            break;
        }
        if (ch == '\\' && i + 1 < json.size())
        {
            ++i;
            switch (json[i])
            {
            case '\"':
                result += '\"';
                break;
            case '\\':
                result += '\\';
                break;
            case 'b':
                result += '\b';
                break;
            case 'f':
                result += '\f';
                break;
            case 'n':
                result += '\n';
                break;
            case 'r':
                result += '\r';
                break;
            case 't':
                result += '\t';
                break;
            default:
                result += json[i];
                break;
            }
        }
        else
        {
            result += ch;
        }
        ++i;
    }
    return result;
}

[[nodiscard]] auto make_channel_pair() -> ChannelPair
{
    auto [server_fd, client_fd] = make_socketpair();

    auto pair = ChannelPair{};
    auto server_ex = std::exception_ptr{};
    auto client_ex = std::exception_ptr{};

    auto t1 = std::thread{[&]() {
        try
        {
            pair.server = std::make_unique<merovingian::ipc::IpcChannel>(std::move(server_fd),
                                                                         merovingian::ipc::IpcChannel::Role::server);
        }
        catch (...)
        {
            server_ex = std::current_exception();
        }
    }};
    auto t2 = std::thread{[&]() {
        try
        {
            pair.client = std::make_unique<merovingian::ipc::IpcChannel>(std::move(client_fd),
                                                                         merovingian::ipc::IpcChannel::Role::client);
        }
        catch (...)
        {
            client_ex = std::current_exception();
        }
    }};
    t1.join();
    t2.join();

    REQUIRE(server_ex == nullptr);
    REQUIRE(client_ex == nullptr);
    REQUIRE(pair.server != nullptr);
    REQUIRE(pair.client != nullptr);
    return pair;
}

} // namespace

SCENARIO("IpcChannel performs encrypted key exchange on construction", "[ipc][channel][security]")
{
    GIVEN("a socketpair with server and client fds")
    {
        WHEN("both sides construct IpcChannel concurrently")
        {
            auto pair = make_channel_pair();

            THEN("both channels are constructed without exception")
            {
                CHECK(pair.server != nullptr);
                CHECK(pair.client != nullptr);
            }

            AND_THEN("both channels report healthy")
            {
                CHECK(pair.server->healthy());
                CHECK(pair.client->healthy());
            }

            pair.server->stop();
            pair.client->stop();
        }
    }
}

SCENARIO("IpcChannel delivers a request and matching response", "[ipc][channel][request_response]")
{
    GIVEN("a connected server and client channel pair")
    {
        auto pair = make_channel_pair();

        auto received = std::string{};
        auto received_id = std::uint64_t{0U};

        // Server echoes every request back as a response.
        pair.server->set_request_handler([&pair, &received, &received_id](std::uint64_t id, std::string json) {
            received_id = id;
            received = json;
            pair.server->send_response(id, R"({"type":"echo_reply","ok":true})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("the client sends a request")
        {
            auto const body = R"({"type":"ping","data":"hello"})";
            auto const timeout = std::chrono::seconds{5};
            auto const reply = pair.client->send_request(body, timeout);

            THEN("the client receives a reply")
            {
                REQUIRE(reply.has_value());
                CHECK(reply->find("echo_reply") != std::string::npos);
            }

            AND_THEN("the server received the request body")
            {
                CHECK(received.find("ping") != std::string::npos);
                CHECK(received.find("hello") != std::string::npos);
            }

            AND_THEN("the reply_to id is present in the reply frame")
            {
                auto const id_str = std::to_string(received_id);
                CHECK(reply->find(id_str) != std::string::npos);
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel delivers a notification without expecting a reply", "[ipc][channel][notification]")
{
    GIVEN("a connected server and client channel pair")
    {
        auto pair = make_channel_pair();
        auto notified = std::atomic<bool>{false};

        pair.server->set_request_handler([&notified](std::uint64_t /*id*/, std::string /*json*/) {
            notified.store(true);
        });
        pair.server->start();
        pair.client->start();

        WHEN("the client sends a notification")
        {
            pair.client->send_notification(R"({"type":"event"})");

            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            while (!notified.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }

            THEN("the server receives the notification")
            {
                CHECK(notified.load());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel send_request returns nullopt on timeout when no reply is sent", "[ipc][channel][timeout]")
{
    GIVEN("a server that receives but never replies")
    {
        auto pair = make_channel_pair();

        pair.server->set_request_handler([](std::uint64_t /*id*/, std::string /*json*/) {
        });
        pair.server->start();
        pair.client->start();

        WHEN("the client sends a request with a short timeout")
        {
            auto const reply = pair.client->send_request(R"({"type":"wait"})", std::chrono::seconds{1});

            THEN("the reply is nullopt")
            {
                CHECK(!reply.has_value());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcEd25519Provider routes sign through channel and returns correct base64 signature",
         "[ipc][ed25519][sign_back_channel]")
{
    GIVEN("a connected channel pair and a deterministic main-side signing provider")
    {
        auto pair = make_channel_pair();

        struct FakeProvider final : merovingian::crypto::Ed25519Provider
        {
            [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& /*key*/,
                                    std::string_view /*message*/) -> merovingian::crypto::SignatureResult override
            {
                return {merovingian::crypto::Ed25519Signature{std::string(crypto_sign_BYTES, '\xab')}, {}};
            }

            [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const& /*public_key*/,
                                      std::string_view /*message*/,
                                      merovingian::crypto::Ed25519Signature const& /*signature*/)
                -> merovingian::crypto::VerificationResult override
            {
                return {false, "not implemented"};
            }
        };

        auto fake = FakeProvider{};

        pair.server->set_request_handler([&pair, &fake](std::uint64_t id, std::string json) {
            if (json_get_str(json, "type") != "sign_request")
            {
                return;
            }
            auto const key_id = merovingian::crypto::Ed25519SecretKeyHandle{json_get_str(json, "key_id")};
            auto const canonical = json_get_str(json, "canonical_json");
            auto const result = fake.sign(key_id, canonical);
            auto const b64 = merovingian::events::matrix_base64_from_bytes(result.signature.bytes);
            pair.server->send_response(id, std::string{"{\"type\":\"sign_response\",\"signature\":\""} + b64 + "\"}");
        });
        pair.server->start();
        pair.client->start();

        WHEN("the provider's sign is invoked over IPC")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{pair.client.get()};
            auto const result =
                provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:worker-test"}, "hello world");

            THEN("the signature bytes match the fake provider's output")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.signature.bytes == std::string(crypto_sign_BYTES, '\xab'));
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}
