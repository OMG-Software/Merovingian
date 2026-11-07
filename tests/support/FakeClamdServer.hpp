// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::tests
{

// A stand-in for clamd on a temporary AF_UNIX socket (ADR-0565). It reads one INSTREAM exchange per connection,
// records the bytes it was sent, and answers with `reply` (sent verbatim, so include the NUL clamd appends), or
// never answers when `reply` is empty (the timeout case). Assertions belong on the test's main thread: read
// `received_streams()` and `connections()` there, after the exchange, never from the server thread.
class FakeClamdServer final
{
public:
    // `reply` nullopt: read the whole stream, then say nothing until stopped.
    FakeClamdServer(std::string socket_path, std::optional<std::string> reply)
        : m_path{std::move(socket_path)}
        , m_reply{std::move(reply)}
    {
        ::unlink(m_path.c_str());
        m_listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
        auto address = sockaddr_un{};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, m_path.c_str(), m_path.size());
        if (m_listener < 0 || ::bind(m_listener, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) != 0 ||
            ::listen(m_listener, 8) != 0)
        {
            m_ok = false;
            return;
        }
        m_thread = std::thread{[this] {
            serve();
        }};
    }

    FakeClamdServer(FakeClamdServer const&) = delete;
    auto operator=(FakeClamdServer const&) -> FakeClamdServer& = delete;
    FakeClamdServer(FakeClamdServer&&) = delete;
    auto operator=(FakeClamdServer&&) -> FakeClamdServer& = delete;

    ~FakeClamdServer()
    {
        m_stop.store(true);
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        if (m_listener >= 0)
        {
            ::close(m_listener);
        }
        ::unlink(m_path.c_str());
    }

    [[nodiscard]] auto ok() const noexcept -> bool
    {
        return m_ok;
    }

    // The payload of every completed stream: the bytes between the INSTREAM command and the zero-length chunk.
    [[nodiscard]] auto received_streams() const -> std::vector<std::string>
    {
        auto const lock = std::scoped_lock{m_mutex};
        return m_streams;
    }

    // Connections accepted so far.
    [[nodiscard]] auto connections() const -> std::size_t
    {
        auto const lock = std::scoped_lock{m_mutex};
        return m_connections;
    }

private:
    auto serve() -> void
    {
        while (!m_stop.load())
        {
            auto listener = pollfd{m_listener, POLLIN, 0};
            if (::poll(&listener, 1, 20) <= 0)
            {
                continue;
            }
            auto const client = ::accept(m_listener, nullptr, nullptr);
            if (client < 0)
            {
                continue;
            }
            {
                auto const lock = std::scoped_lock{m_mutex};
                ++m_connections;
            }
            handle(client);
            ::close(client);
        }
    }

    // Reads exactly `count` bytes unless the server is stopping or the peer goes away.
    [[nodiscard]] auto read_exact(int client, std::size_t count) -> std::optional<std::string>
    {
        auto data = std::string{};
        while (data.size() < count)
        {
            if (m_stop.load())
            {
                return std::nullopt;
            }
            auto descriptor = pollfd{client, POLLIN, 0};
            if (::poll(&descriptor, 1, 20) <= 0)
            {
                continue;
            }
            char buffer[4096];
            auto const wanted = std::min(sizeof(buffer), count - data.size());
            auto const received = ::recv(client, buffer, wanted, 0);
            if (received <= 0)
            {
                return std::nullopt;
            }
            data.append(buffer, static_cast<std::size_t>(received));
        }
        return data;
    }

    auto handle(int client) -> void
    {
        auto const command = read_exact(client, 10U);
        if (!command.has_value() || *command != std::string{"zINSTREAM\0", 10U})
        {
            return;
        }
        auto stream = std::string{};
        while (true)
        {
            auto const prefix = read_exact(client, 4U);
            if (!prefix.has_value())
            {
                return;
            }
            auto length = std::uint32_t{0U};
            for (auto const c : *prefix)
            {
                length = (length << 8U) | static_cast<std::uint8_t>(c);
            }
            if (length == 0U)
            {
                break;
            }
            auto const chunk = read_exact(client, length);
            if (!chunk.has_value())
            {
                return;
            }
            stream += *chunk;
        }
        {
            auto const lock = std::scoped_lock{m_mutex};
            m_streams.push_back(std::move(stream));
        }
        if (m_reply.has_value())
        {
            std::ignore = ::send(client, m_reply->data(), m_reply->size(), MSG_NOSIGNAL);
            return;
        }
        // Silent: hold the connection open until the server stops or the peer hangs up.
        while (!m_stop.load())
        {
            auto descriptor = pollfd{client, POLLIN, 0};
            if (::poll(&descriptor, 1, 20) > 0)
            {
                char byte = 0;
                if (::recv(client, &byte, 1, 0) <= 0)
                {
                    return;
                }
            }
        }
    }

    std::string m_path;
    std::optional<std::string> m_reply;
    int m_listener{-1};
    bool m_ok{true};
    std::atomic<bool> m_stop{false};
    mutable std::mutex m_mutex{};
    std::vector<std::string> m_streams{};
    std::size_t m_connections{0U};
    std::thread m_thread{};
};

} // namespace merovingian::tests
