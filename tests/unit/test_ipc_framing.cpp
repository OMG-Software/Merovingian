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
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/ipc_ed25519_provider.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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

// Derive a deterministic IpcAuthKey from fixed test material so both sides of
// a test channel pair share the same authenticated-handshake key without
// touching the filesystem.
[[nodiscard]] auto make_test_auth_key(std::string_view seed = "ipc-auth-test-key") -> merovingian::crypto::IpcAuthKey
{
    auto const key = merovingian::crypto::derive_ipc_auth_key(
        std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(seed.data()), seed.size()});
    REQUIRE(key.has_value());
    return *key;
}

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

    // Both sides must share the same IpcAuthKey for the authenticated handshake.
    auto const auth_key = make_test_auth_key();

    auto t1 = std::thread{[&]() {
        try
        {
            pair.server = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(server_fd), merovingian::ipc::IpcChannel::Role::server, auth_key);
        }
        catch (...)
        {
            server_ex = std::current_exception();
        }
    }};
    auto t2 = std::thread{[&]() {
        try
        {
            pair.client = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(client_fd), merovingian::ipc::IpcChannel::Role::client, auth_key);
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

// Construct a server and client with MISMATCHED IpcAuthKeys. Used to prove the
// authenticated handshake fails closed: construction must throw rather than
// silently establishing an unauthenticated channel.
[[nodiscard]] auto make_mismatched_channel_pair() -> std::pair<std::exception_ptr, std::exception_ptr>
{
    auto [server_fd, client_fd] = make_socketpair();
    auto server_ex = std::exception_ptr{};
    auto client_ex = std::exception_ptr{};
    auto server_ptr = std::unique_ptr<merovingian::ipc::IpcChannel>{};
    auto client_ptr = std::unique_ptr<merovingian::ipc::IpcChannel>{};
    auto const server_key = make_test_auth_key("server-only-key");
    auto const client_key = make_test_auth_key("client-only-key");

    auto t1 = std::thread{[&]() {
        try
        {
            server_ptr = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(server_fd), merovingian::ipc::IpcChannel::Role::server, server_key);
        }
        catch (...)
        {
            server_ex = std::current_exception();
        }
    }};
    auto t2 = std::thread{[&]() {
        try
        {
            client_ptr = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(client_fd), merovingian::ipc::IpcChannel::Role::client, client_key);
        }
        catch (...)
        {
            client_ex = std::current_exception();
        }
    }};
    t1.join();
    t2.join();
    return {server_ex, client_ex};
}

} // namespace

SCENARIO("frame_bytes_for_response_cap sizes the frame off the base64-encoded response, not the raw body",
         "[ipc][channel][framing]")
{
    GIVEN("the default 16 MiB OutboundCall response cap")
    {
        WHEN("the frame budget is computed")
        {
            auto const frame_bytes = merovingian::ipc::frame_bytes_for_response_cap(16U * 1024U * 1024U);

            THEN("it never returns less than kIpcMaxFrameBytes, preserving today's behaviour")
            {
                REQUIRE(frame_bytes >= merovingian::ipc::kIpcMaxFrameBytes);
            }
        }
    }

    GIVEN("a large custom response cap, e.g. join_response_max_size=64MiB for a huge room's send_join")
    {
        WHEN("the frame budget is computed")
        {
            auto const frame_bytes = merovingian::ipc::frame_bytes_for_response_cap(64U * 1024U * 1024U);

            THEN("it comfortably exceeds the base64-encoded 4/3 expansion of the response cap")
            {
                REQUIRE(frame_bytes > (64U * 1024U * 1024U * 4U) / 3U);
            }
        }
    }

    GIVEN("a response cap of zero")
    {
        WHEN("the frame budget is computed")
        {
            auto const frame_bytes = merovingian::ipc::frame_bytes_for_response_cap(0U);

            THEN("it falls back to kIpcMaxFrameBytes rather than an unusably small frame")
            {
                REQUIRE(frame_bytes == merovingian::ipc::kIpcMaxFrameBytes);
            }
        }
    }
}

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

SCENARIO("IpcChannel rejects a peer that lacks the shared IPC auth key", "[ipc][channel][security]")
{
    GIVEN("a socketpair where the server and client derive different IpcAuthKeys")
    {
        WHEN("both sides attempt the authenticated handshake")
        {
            auto const [server_ex, client_ex] = make_mismatched_channel_pair();

            THEN("at least one side throws a runtime_error (fail-closed)")
            {
                // The MAC exchange is symmetric: the side that receives the
                // wrong peer MAC throws. Exactly which side throws depends on
                // scheduling, but the handshake must not silently succeed.
                REQUIRE((server_ex != nullptr || client_ex != nullptr));
            }
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

SCENARIO("IpcChannel stop is idempotent and healthy reflects the stopped state", "[ipc][channel][lifecycle]")
{
    GIVEN("a connected channel pair")
    {
        auto pair = make_channel_pair();

        THEN("both channels report healthy before start")
        {
            CHECK(pair.server->healthy());
            CHECK(pair.client->healthy());
        }

        WHEN("the client is stopped twice")
        {
            pair.client->stop();
            pair.client->stop();

            THEN("the channel reports not healthy")
            {
                CHECK_FALSE(pair.client->healthy());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel send_request returns nullopt on a stopped channel", "[ipc][channel][lifecycle]")
{
    GIVEN("a connected channel pair")
    {
        auto pair = make_channel_pair();
        pair.server->start();
        pair.client->start();

        WHEN("the client is stopped before sending a request")
        {
            pair.client->stop();
            auto const reply = pair.client->send_request(R"({"type":"ping"})", std::chrono::seconds{1});

            THEN("the request returns nullopt immediately")
            {
                CHECK_FALSE(reply.has_value());
            }
        }

        pair.server->stop();
    }
}

SCENARIO("IpcChannel handles multiple concurrent requests with matching replies", "[ipc][channel][concurrent]")
{
    GIVEN("a server that echoes each request id back")
    {
        auto pair = make_channel_pair();

        pair.server->set_request_handler([server = pair.server.get()](std::uint64_t id, std::string json) {
            auto const id_str = std::to_string(id);
            // The channel injects "id"/"reply_to" into every frame, so the body
            // must NOT reuse those keys (canonicaljson rejects duplicate keys,
            // which would make the client's reader_loop drop the reply). Echo
            // the request id under a non-conflicting key instead.
            server->send_response(id,
                                  std::string{R"({"type":"echo","echoed_id":)"} + id_str + R"(,"json":)" + json + "}");
        });
        pair.server->start();
        pair.client->start();

        WHEN("two requests are sent concurrently")
        {
            auto reply_a = std::optional<std::string>{};
            auto reply_b = std::optional<std::string>{};
            auto t1 = std::thread{[client = pair.client.get(), &reply_a]() {
                reply_a = client->send_request(R"({"type":"a"})", std::chrono::seconds{5});
            }};
            auto t2 = std::thread{[client = pair.client.get(), &reply_b]() {
                reply_b = client->send_request(R"({"type":"b"})", std::chrono::seconds{5});
            }};
            t1.join();
            t2.join();

            THEN("both replies arrive and contain distinct request ids")
            {
                REQUIRE(reply_a.has_value());
                REQUIRE(reply_b.has_value());
                CHECK(reply_a->find("\"type\":\"echo\"") != std::string::npos);
                CHECK(reply_b->find("\"type\":\"echo\"") != std::string::npos);
                CHECK(reply_a->find("\"type\":\"a\"") != std::string::npos);
                CHECK(reply_b->find("\"type\":\"b\"") != std::string::npos);
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel routes responses while a request handler is blocked on a caller-held lock",
         "[ipc][channel][dispatch]")
{
    GIVEN("a server whose request handler needs a mutex held by a thread that is waiting on send_request")
    {
        // Models the federation-worker drip-feed deadlock: a worker relay
        // thread holds runtime.mutex across a pdu_ingest send_request to
        // main, and main sends a room_sync notification — whose handler
        // needs that same mutex — immediately before the pdu_ingest
        // response. If the channel invokes request handlers inline on its
        // reader thread, the reader blocks on the mutex and never routes
        // the response sitting right behind the notification; the
        // send_request can only time out.
        auto pair = make_channel_pair();

        auto shared_mutex = std::mutex{};
        auto poke_handled = std::atomic<bool>{false};

        // Server side ("worker"): handling a poke requires shared_mutex.
        pair.server->set_request_handler([&shared_mutex, &poke_handled](std::uint64_t /*id*/, std::string /*json*/) {
            auto const guard = std::lock_guard{shared_mutex};
            poke_handled.store(true);
        });
        // Client side ("main"): answering a query first pokes the server,
        // then replies — the poke frame precedes the response frame on the
        // wire, exactly as notify_room_changed precedes send_response.
        pair.client->set_request_handler([client = pair.client.get()](std::uint64_t id, std::string /*json*/) {
            client->send_notification(R"({"type":"poke"})");
            client->send_response(id, R"({"type":"query_result"})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("the server sends a request while holding the mutex its own request handler needs")
        {
            auto reply = std::optional<std::string>{};
            {
                auto const guard = std::lock_guard{shared_mutex};
                reply = pair.server->send_request(R"({"type":"query"})", std::chrono::seconds{5});
            }

            THEN("the response is delivered instead of timing out, and the poke completes once the lock is free")
            {
                REQUIRE(reply.has_value());
                CHECK(reply->find("query_result") != std::string::npos);

                // The mutex is released now, so the queued poke handler must
                // be able to run to completion before the channels stop.
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
                while (!poke_handled.load() && std::chrono::steady_clock::now() < deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
                CHECK(poke_handled.load());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel dispatches request frames in arrival order", "[ipc][channel][dispatch]")
{
    GIVEN("a server that records the type of every notification it handles")
    {
        auto pair = make_channel_pair();

        auto seen_mutex = std::mutex{};
        auto seen = std::vector<std::string>{};

        pair.server->set_request_handler([&seen_mutex, &seen](std::uint64_t /*id*/, std::string json) {
            auto const guard = std::lock_guard{seen_mutex};
            seen.push_back(json_get_str(json, "type"));
        });
        pair.server->start();
        pair.client->start();

        WHEN("the client sends several notifications from one thread")
        {
            auto const sent = std::vector<std::string>{"n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7"};
            for (auto const& type : sent)
            {
                pair.client->send_notification(std::string{R"({"type":")"} + type + R"("})");
            }

            THEN("the server handles every notification in the order it was sent")
            {
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
                while (std::chrono::steady_clock::now() < deadline)
                {
                    {
                        auto const guard = std::lock_guard{seen_mutex};
                        if (seen.size() == sent.size())
                        {
                            break;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
                auto const guard = std::lock_guard{seen_mutex};
                REQUIRE(seen == sent);
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel request handlers can offload slow work to a thread pool without stalling later requests",
         "[ipc][channel][dispatch][thread_pool]")
{
    GIVEN("a connected channel pair whose server delegates every request to a thread pool")
    {
        auto pair = make_channel_pair();

        // Two workers are enough: one runs the slow request while the other
        // handles the fast request concurrently.
        auto handler_pool = merovingian::net::ThreadPool{2U};

        auto results_mutex = std::mutex{};
        auto results = std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>>{};

        pair.server->set_request_handler([server = pair.server.get(), &handler_pool, &results_mutex,
                                          &results](std::uint64_t id, std::string json) {
            auto const type = json_get_str(json, "type");
            // Offload the real work so the dispatch thread returns immediately
            // and can route the next frame. This mirrors WorkerPool behaviour.
            std::ignore = handler_pool.submit([server, id, type, json = std::move(json), &results_mutex, &results]() {
                if (type == "slow")
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{400});
                }

                server->send_response(id, std::string{"{\"type\":\"reply\",\"req_type\":\""} + type + "\"}");

                {
                    auto const guard = std::lock_guard{results_mutex};
                    results.emplace_back(type, std::chrono::steady_clock::now());
                }
            });
        });
        pair.server->start();
        pair.client->start();

        WHEN("a slow request and a fast request are sent concurrently")
        {
            auto slow_reply = std::optional<std::string>{};
            auto fast_reply = std::optional<std::string>{};
            auto reply_times_mutex = std::mutex{};
            auto slow_reply_time = std::chrono::steady_clock::time_point{};
            auto fast_reply_time = std::chrono::steady_clock::time_point{};

            auto slow_thread = std::thread{[&pair, &slow_reply, &reply_times_mutex, &slow_reply_time]() {
                slow_reply = pair.client->send_request(R"({"type":"slow"})", std::chrono::seconds{5});
                auto const guard = std::lock_guard{reply_times_mutex};
                slow_reply_time = std::chrono::steady_clock::now();
            }};
            auto fast_thread = std::thread{[&pair, &fast_reply, &reply_times_mutex, &fast_reply_time]() {
                fast_reply = pair.client->send_request(R"({"type":"fast"})", std::chrono::seconds{5});
                auto const guard = std::lock_guard{reply_times_mutex};
                fast_reply_time = std::chrono::steady_clock::now();
            }};

            slow_thread.join();
            fast_thread.join();

            THEN("both requests receive replies")
            {
                REQUIRE(slow_reply.has_value());
                REQUIRE(fast_reply.has_value());
            }

            AND_THEN("the fast request is replied to before the slow request finishes")
            {
                {
                    auto const guard = std::lock_guard{reply_times_mutex};
                    REQUIRE(fast_reply_time < slow_reply_time);
                }

                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
                while (std::chrono::steady_clock::now() < deadline)
                {
                    {
                        auto const guard = std::lock_guard{results_mutex};
                        if (results.size() == 2U)
                        {
                            break;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }

                auto const guard = std::lock_guard{results_mutex};
                REQUIRE(results.size() == 2U);
                REQUIRE(results[0].first == "fast");
                REQUIRE(results[1].first == "slow");
            }
        }

        // Stop the pool before the channels so no in-flight worker tries to
        // send_response after the channel has been destroyed.
        handler_pool.request_stop();
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

SCENARIO("IpcEd25519Provider surfaces IPC and protocol errors instead of returning invalid signatures",
         "[ipc][ed25519][error-paths]")
{
    GIVEN("a connected channel pair and a worker-side provider")
    {
        auto pair = make_channel_pair();

        WHEN("the provider is constructed with a null channel")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{nullptr};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:x"}, "msg");

            THEN("sign returns an error without signature bytes")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.signature.bytes.empty());
            }
        }

        pair.server->set_request_handler([server = pair.server.get()](std::uint64_t id, std::string /*json*/) {
            server->send_response(id, R"({"type":"not_sign_response"})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("main replies with an unexpected frame type")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{pair.client.get()};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:x"}, "msg");

            THEN("the provider returns an error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.signature.bytes.empty());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcEd25519Provider rejects malformed sign_response payloads", "[ipc][ed25519][error-paths]")
{
    GIVEN("a connected channel pair where main returns malformed sign responses")
    {
        auto pair = make_channel_pair();

        pair.server->set_request_handler([server = pair.server.get()](std::uint64_t id, std::string /*json*/) {
            server->send_response(id, R"({"type":"sign_response","signature":"","error":""})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("main returns an empty signature field")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{pair.client.get()};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:x"}, "msg");

            THEN("the provider reports an empty signature error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.signature.bytes.empty());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }

    GIVEN("a connected channel pair where main returns a non-base64 signature")
    {
        auto pair = make_channel_pair();

        pair.server->set_request_handler([server = pair.server.get()](std::uint64_t id, std::string /*json*/) {
            server->send_response(id, R"({"type":"sign_response","signature":"not-base64!"})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("the signature cannot be base64-decoded")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{pair.client.get()};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:x"}, "msg");

            THEN("the provider reports a shape error")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.signature.bytes.size() != crypto_sign_BYTES);
            }
        }

        pair.server->stop();
        pair.client->stop();
    }

    GIVEN("a connected channel pair where main reports a signing error")
    {
        auto pair = make_channel_pair();

        pair.server->set_request_handler([server = pair.server.get()](std::uint64_t id, std::string /*json*/) {
            server->send_response(id, R"({"type":"sign_response","signature":"","error":"main failed"})");
        });
        pair.server->start();
        pair.client->start();

        WHEN("main includes an error field")
        {
            auto provider = merovingian::ipc::IpcEd25519Provider{pair.client.get()};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:x"}, "msg");

            THEN("the provider forwards the error")
            {
                REQUIRE(result.error.find("main failed") != std::string::npos);
                REQUIRE(result.signature.bytes.empty());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}

SCENARIO("IpcChannel dispatch thread survives an unhandled request-handler exception",
         "[ipc][channel][dispatch][error-paths]")
{
    GIVEN("a connected channel pair with a request handler that always throws")
    {
        REQUIRE(sodium_init() >= 0);

        auto pair = make_channel_pair();

        auto handler_ran = std::atomic<bool>{false};
        pair.server->set_request_handler([&handler_ran](std::uint64_t /*id*/, std::string /*json*/) {
            handler_ran.store(true);
            throw std::runtime_error{"boom"};
        });
        pair.server->start();
        pair.client->start();

        WHEN("the client sends a request and the server handler throws")
        {
            auto const reply = pair.client->send_request(R"({"type":"test"})", std::chrono::seconds{10});

            THEN("the client sees no reply because the channel became unhealthy")
            {
                REQUIRE_FALSE(reply.has_value());
            }
            AND_THEN("the throwing handler actually ran")
            {
                REQUIRE(handler_ran.load());
            }
            AND_THEN("the server channel reports unhealthy")
            {
                REQUIRE_FALSE(pair.server->healthy());
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}
// Regression for #451: a body of exactly "{}" (no fields) was appended after
// the frame header comma, producing {"id":1,} — invalid JSON. The peer's
// parser rejected the frame and marked the channel unhealthy, tearing down
// the worker link.
SCENARIO("IpcChannel build_frame emits valid JSON for an empty-object body", "[ipc][channel][framing]")
{
    GIVEN("a healthy channel pair")
    {
        auto pair = make_channel_pair();

        WHEN("frames are built from empty and non-empty bodies")
        {
            auto const empty_body = pair.server->build_frame(1U, std::nullopt, "{}");
            auto const empty_reply = pair.server->build_frame(2U, std::uint64_t{1U}, "{}");
            auto const with_field = pair.server->build_frame(3U, std::nullopt, R"({"type":"ping"})");

            THEN("no frame carries a trailing comma")
            {
                REQUIRE(empty_body == R"({"id":1})");
                REQUIRE(empty_reply == R"({"id":2,"reply_to":1})");
                REQUIRE(with_field == R"({"id":3,"type":"ping"})");
            }
        }

        pair.server->stop();
        pair.client->stop();
    }
}
