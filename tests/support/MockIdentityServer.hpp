// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "TlsTestCertificate.hpp"
#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/homeserver/TlsServerContextResult.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/identity/TestForcedIdentityResolution.hpp"
#include "merovingian/net/TcpAcceptor.hpp"
#include "TlsMockServer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::tests::tls_mock
{

// A trusted mock identity server on a real loopback TLS socket, for the tests
// that exercise the identity-server-delegated 3PID flows (requestToken,
// getValidated3pid, bind). It serves any number of requests until destroyed;
// each response is selected by a substring of the request line (method + path),
// and a request matching none is answered 404 M_UNRECOGNIZED. Responses are
// reusable, not consumed, so a test need not predict how many times the
// homeserver calls an endpoint. The server thread makes no assertions (Catch2 is
// not thread-safe); tests read `requests()` from the main thread.
//
// The certificate CN is the IS host: the homeserver verifies the peer name
// against the URL host, so "localhost" would fail the handshake.
class MockIdentityServer final
{
public:
    using Responses = std::vector<std::pair<std::string, std::string>>;

    explicit MockIdentityServer(Responses responses, std::string host = "is.localhost.test")
        : host_{std::move(host)}
        , responses_{std::move(responses)}
        , certificate_{write_test_tls_certificate(host_)}
        , tls_{merovingian::homeserver::make_tls_server_context(certificate_.certificate_file,
                                                                certificate_.private_key_file)}
    {
        REQUIRE(tls_.ok());
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        REQUIRE(acceptor_.bound_port() > 0U);
        thread_ = std::thread{[this] {
            serve();
        }};
    }

    ~MockIdentityServer()
    {
        stop_.store(true);
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    MockIdentityServer(MockIdentityServer const&) = delete;
    auto operator=(MockIdentityServer const&) -> MockIdentityServer& = delete;
    MockIdentityServer(MockIdentityServer&&) = delete;
    auto operator=(MockIdentityServer&&) -> MockIdentityServer& = delete;

    // The `id_server` value a client sends: host:port.
    [[nodiscard]] auto host_port() const -> std::string
    {
        return host_ + ":" + std::to_string(acceptor_.bound_port());
    }

    [[nodiscard]] auto base_url() const -> std::string
    {
        return "https://" + host_port();
    }

    // The bound loopback port and the PEM of the test CA that issued its certificate, for
    // tests that pin this server's host themselves (URL previews pin it through
    // HomeserverRuntime::test_forced_outbound_resolution).
    [[nodiscard]] auto port() const -> std::uint16_t
    {
        return acceptor_.bound_port();
    }

    [[nodiscard]] auto certificate_pem() const -> std::string const&
    {
        return certificate_.certificate_pem;
    }

    // A cooperative identity server for tests that only need a 3PID to end up
    // associated with an account: requestToken is answered with the sid
    // "email-sid" or "msisdn-sid", and getValidated3pid for that sid reports the
    // matching entry of `validated` (medium, address) validated at
    // `cooperative_validated_at_ms`. Bind and unbind succeed.
    [[nodiscard]] static auto cooperative_responses(std::vector<std::pair<std::string, std::string>> const& validated)
        -> Responses
    {
        auto responses = Responses{
            {"validate/email/requestToken",  json_http_response("200 OK", R"({"sid":"email-sid"})") },
            {"validate/msisdn/requestToken", json_http_response("200 OK", R"({"sid":"msisdn-sid"})")},
            {"3pid/bind",                    json_http_response("200 OK", "{}")                     },
            {"3pid/unbind",                  json_http_response("200 OK", "{}")                     },
        };
        for (auto const& [medium, address] : validated)
        {
            responses.emplace_back("sid=" + medium + "-sid",
                                   json_http_response("200 OK", R"({"address":")" + address + R"(","medium":")" +
                                                                    medium + R"(","validated_at":)" +
                                                                    std::to_string(cooperative_validated_at_ms) + "}"));
        }
        return responses;
    }

    static constexpr auto cooperative_validated_at_ms = std::uint64_t{1700000000000U};

    // Returns `json_object` (a JSON object literal) with this server named as
    // the request's id_server, together with an IS access token: the pair that
    // delegates a requestToken call to it.
    [[nodiscard]] auto with_identity_server(std::string json_object) const -> std::string
    {
        auto const closing = json_object.rfind('}');
        REQUIRE(closing != std::string::npos);
        json_object.insert(closing, R"(,"id_server":")" + host_port() + R"(","id_access_token":"opaque")");
        return json_object;
    }

    // Marks this server trusted and pins its host to loopback with its
    // test CA. `Runtime` is a ClientServerRuntime; it is a
    // template parameter so this header stays free of the client-server header.
    template <typename Runtime>
    auto install(Runtime& runtime) const -> void
    {
        auto& identity_server = runtime.homeserver.config.server().identity_server;
        identity_server.trusted_servers = {base_url()};
        runtime.homeserver.test_forced_identity_resolution[host_] =
            merovingian::identity::TestForcedIdentityResolution{{"127.0.0.1"}, certificate_.certificate_pem};
    }

    // Raw bytes of every request received so far, in arrival order.
    [[nodiscard]] auto requests() const -> std::vector<std::string>
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        return captured_;
    }

    // Number of received requests whose bytes contain `needle`.
    [[nodiscard]] auto count_requests(std::string_view needle) const -> std::size_t
    {
        auto count = std::size_t{0U};
        for (auto const& request : requests())
        {
            if (request.find(needle) != std::string::npos)
            {
                ++count;
            }
        }
        return count;
    }

    // Makes the server hold any request whose request line contains `needle`
    // until release_stall() is called (or ten seconds pass, so a failed
    // assertion cannot wedge the suite). stall_seen() turns true once such a
    // request has arrived. Call before the traffic starts.
    auto stall_requests_matching(std::string needle) -> void
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        stall_needle_ = std::move(needle);
    }

    [[nodiscard]] auto stall_seen() const noexcept -> std::atomic<bool> const&
    {
        return stall_seen_;
    }

    auto release_stall() noexcept -> void
    {
        stall_released_.store(true);
    }

private:
    auto serve() noexcept -> void
    {
        while (!stop_.load())
        {
            auto const client_fd = accept_loopback(acceptor_, 50);
            if (client_fd < 0)
            {
                continue;
            }
            auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
            auto tls_result = merovingian::homeserver::accept_tls_connection(*tls_.context, client_fd, 5000);
            if (!tls_result.connection.has_value())
            {
                continue;
            }
            auto& connection = *tls_result.connection;
            auto buffer = std::array<char, 8192>{};
            auto request_bytes = std::string{};
            while (request_bytes.find("\r\n\r\n") == std::string::npos)
            {
                auto const bytes_read = connection.read(buffer.data(), buffer.size());
                if (bytes_read <= 0)
                {
                    break;
                }
                request_bytes.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            }
            auto const request_line = request_bytes.substr(0U, request_bytes.find("\r\n"));
            auto stalls = false;
            {
                auto const lock = std::lock_guard<std::mutex>{mutex_};
                captured_.push_back(request_bytes);
                stalls = !stall_needle_.empty() && request_line.find(stall_needle_) != std::string::npos;
            }
            if (stalls)
            {
                stall_seen_.store(true);
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
                while (!stall_released_.load() && !stop_.load() && std::chrono::steady_clock::now() < deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            }
            auto response = json_http_response("404 Not Found", R"({"errcode":"M_UNRECOGNIZED","error":"no route"})");
            for (auto const& [needle, canned] : responses_)
            {
                if (request_line.find(needle) != std::string::npos)
                {
                    response = canned;
                    break;
                }
            }
            std::ignore = connection.write(response);
        }
    }

    std::string host_;
    Responses responses_;
    TlsTestCertificate certificate_;
    merovingian::homeserver::TlsServerContextResult tls_;
    merovingian::net::TcpAcceptor acceptor_{};
    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_{};
    std::vector<std::string> captured_{};
    std::string stall_needle_{};
    std::atomic<bool> stall_seen_{false};
    std::atomic<bool> stall_released_{false};
    std::thread thread_{};
};

} // namespace merovingian::tests::tls_mock
