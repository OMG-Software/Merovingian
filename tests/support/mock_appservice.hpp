// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// A loopback application service for tests that drive the homeserver's outbound
// Application Service API calls (transactions, ping, queries) and assert on the
// bytes it actually received.
//
// It listens on 127.0.0.1 on a free port and serves one connection at a time on
// its own thread. Every request is recorded; the answer is the global status
// (200 until changed) unless a path prefix has its own. `go_silent` makes it
// accept a request and never answer, which is how a test makes the homeserver's
// outbound timeout fire. All state is guarded by one mutex, so a test thread may
// change the answers and read the requests while the server runs; assertions
// stay on the test thread (Catch2 assertions are not thread-safe).

#include "merovingian/net/tcp_acceptor.hpp"
#include "tls_mock_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <poll.h>
#include <unistd.h>

namespace merovingian::tests
{

struct CapturedAppserviceRequest final
{
    std::string method{};
    std::string target{};
    std::string authorization{};
    std::string body{};
    std::uint16_t answered_status{0U};
};

class MockAppservice final
{
public:
    MockAppservice()
    {
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        m_port = m_acceptor.bound_port();
        REQUIRE(m_port > 0U);
        m_thread = std::thread{[this] {
            serve();
        }};
    }

    MockAppservice(MockAppservice const&) = delete;
    MockAppservice(MockAppservice&&) = delete;
    auto operator=(MockAppservice const&) -> MockAppservice& = delete;
    auto operator=(MockAppservice&&) -> MockAppservice& = delete;

    ~MockAppservice()
    {
        m_stop.store(true);
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return m_port;
    }

    [[nodiscard]] auto url() const -> std::string
    {
        return "http://127.0.0.1:" + std::to_string(m_port);
    }

    // The status every request without a path-specific answer gets; any status other than 200 comes
    // with the body {"error":"mock"}.
    auto set_status(std::uint16_t status) -> void
    {
        auto const lock = std::lock_guard{m_mutex};
        m_status = status;
    }

    // The answer to requests whose target starts with `target_prefix`.
    auto set_answer(std::string target_prefix, std::uint16_t status, std::string body) -> void
    {
        auto const lock = std::lock_guard{m_mutex};
        m_answers.push_back({std::move(target_prefix), status, std::move(body)});
    }

    // While set, requests are accepted and read and never answered. The connection is held open
    // until the flag is cleared or the mock is destroyed.
    auto go_silent(bool silent) -> void
    {
        m_silent.store(silent);
    }

    [[nodiscard]] auto requests() const -> std::vector<CapturedAppserviceRequest>
    {
        auto const lock = std::lock_guard{m_mutex};
        return m_requests;
    }

    // The requests whose target starts with `target_prefix`, in arrival order.
    [[nodiscard]] auto requests_to(std::string_view target_prefix) const -> std::vector<CapturedAppserviceRequest>
    {
        auto matching = std::vector<CapturedAppserviceRequest>{};
        for (auto const& request : requests())
        {
            if (request.target.starts_with(target_prefix))
            {
                matching.push_back(request);
            }
        }
        return matching;
    }

    // True once at least `count` requests have arrived, waiting up to `timeout`.
    [[nodiscard]] auto wait_for_requests(std::size_t count, std::chrono::milliseconds timeout) const -> bool
    {
        auto const deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (requests().size() >= count)
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        return requests().size() >= count;
    }

private:
    struct Answer final
    {
        std::string target_prefix{};
        std::uint16_t status{200U};
        std::string body{};
    };

    [[nodiscard]] static auto header_value(std::string const& head, std::string const& name) -> std::string
    {
        auto lowered = head;
        std::ranges::transform(lowered, lowered.begin(), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });
        auto const key = "\r\n" + name + ":";
        auto const at = lowered.find(key);
        if (at == std::string::npos)
        {
            return {};
        }
        auto const value_begin = at + key.size();
        auto const value_end = head.find("\r\n", value_begin);
        auto value = head.substr(value_begin, value_end - value_begin);
        auto const first = value.find_first_not_of(' ');
        return first == std::string::npos ? std::string{} : value.substr(first);
    }

    auto serve() noexcept -> void
    {
        while (!m_stop.load())
        {
            auto const client_fd = tls_mock::accept_loopback(m_acceptor, 25);
            if (client_fd < 0)
            {
                continue;
            }
            handle(client_fd);
            ::close(client_fd);
        }
    }

    auto handle(int client_fd) -> void
    {
        auto buffer = std::array<char, 8192>{};
        auto received = std::string{};
        auto const read_some = [&]() {
            auto pollfd_entry = ::pollfd{client_fd, POLLIN, 0};
            if (::poll(&pollfd_entry, 1U, 2000) <= 0)
            {
                return false;
            }
            auto const bytes_read = ::read(client_fd, buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                return false;
            }
            received.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            return true;
        };
        while (received.find("\r\n\r\n") == std::string::npos)
        {
            if (!read_some())
            {
                return;
            }
        }
        auto const head_end = received.find("\r\n\r\n") + 4U;
        auto const head = received.substr(0U, head_end);
        auto expected = std::size_t{0U};
        if (auto const length = header_value(head, "content-length"); !length.empty())
        {
            expected = static_cast<std::size_t>(std::stoull(length));
        }
        while (received.size() - head_end < expected)
        {
            if (!read_some())
            {
                return;
            }
        }

        auto const request_line = received.substr(0U, received.find("\r\n"));
        auto const method_end = request_line.find(' ');
        auto const target_end = request_line.find(' ', method_end + 1U);

        auto captured = CapturedAppserviceRequest{};
        captured.method = request_line.substr(0U, method_end);
        captured.target = request_line.substr(method_end + 1U, target_end - method_end - 1U);
        captured.authorization = header_value(head, "authorization");
        captured.body = received.substr(head_end, expected);

        auto status = std::uint16_t{200U};
        auto body = std::string{"{}"};
        {
            auto const lock = std::lock_guard{m_mutex};
            status = m_status;
            if (status != 200U)
            {
                body = R"({"error":"mock"})";
            }
            for (auto const& answer : m_answers)
            {
                if (captured.target.starts_with(answer.target_prefix))
                {
                    status = answer.status;
                    body = answer.body;
                }
            }
            captured.answered_status = status;
            m_requests.push_back(captured);
        }

        while (m_silent.load() && !m_stop.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        if (m_silent.load())
        {
            return;
        }
        auto const status_line = std::to_string(status) + (status == 200U ? " OK" : " Mock");
        auto const response = tls_mock::json_http_response(status_line, body);
        std::ignore = ::write(client_fd, response.data(), response.size());
    }

    net::TcpAcceptor m_acceptor{};
    std::uint16_t m_port{0U};
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_silent{false};
    mutable std::mutex m_mutex{};
    std::uint16_t m_status{200U};
    std::vector<Answer> m_answers{};
    std::vector<CapturedAppserviceRequest> m_requests{};
    std::thread m_thread{};
};

} // namespace merovingian::tests
