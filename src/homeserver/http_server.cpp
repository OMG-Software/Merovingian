// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/http_server.hpp"

#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/http/request_limits.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("http_server", event, std::move(fields)));
    }

    // Conservative deadlines for the minimal serve loop. The slowloris policy
    // scaffolding in http/connection_guard.cpp will replace these once
    // connection-level accounting lands.
    constexpr auto receive_timeout_milliseconds = 15000;
    constexpr auto header_terminator = std::string_view{"\r\n\r\n"};

    class ConnectionStream
    {
    public:
        ConnectionStream() = default;
        virtual ~ConnectionStream() = default;

        ConnectionStream(ConnectionStream const&) = delete;
        auto operator=(ConnectionStream const&) -> ConnectionStream& = delete;

        ConnectionStream(ConnectionStream&&) = delete;
        auto operator=(ConnectionStream&&) -> ConnectionStream& = delete;

        [[nodiscard]] virtual auto fd() const noexcept -> int = 0;
        [[nodiscard]] virtual auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t = 0;
        [[nodiscard]] virtual auto write(std::string_view data) noexcept -> std::ptrdiff_t = 0;
    };

    class PlainConnectionStream final : public ConnectionStream
    {
    public:
        explicit PlainConnectionStream(int file_descriptor) noexcept
            : m_fd{file_descriptor}
        {
        }

        [[nodiscard]] auto fd() const noexcept -> int override
        {
            return m_fd;
        }

        [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t override
        {
            return ::recv(m_fd, buffer, capacity, 0);
        }

        [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t override
        {
            // MSG_NOSIGNAL avoids SIGPIPE on early client close (POSIX 2008).
            return ::send(m_fd, data.data(), data.size(), MSG_NOSIGNAL);
        }

    private:
        int m_fd;
    };

    class TlsConnectionStream final : public ConnectionStream
    {
    public:
        explicit TlsConnectionStream(TlsConnection& connection) noexcept
            : m_connection{connection}
        {
        }

        [[nodiscard]] auto fd() const noexcept -> int override
        {
            return m_connection.fd();
        }

        [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t override
        {
            return m_connection.read(buffer, capacity);
        }

        [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t override
        {
            return m_connection.write(data);
        }

    private:
        TlsConnection& m_connection;
    };

    [[nodiscard]] auto header_size_cap(http::RequestLimits const& limits) noexcept -> std::size_t
    {
        auto const headers = static_cast<std::size_t>(limits.max_header_bytes);
        auto const start = static_cast<std::size_t>(limits.max_start_line_bytes);
        // Allow for the start line, the header block, and a trailing CRLFCRLF.
        return start + headers + header_terminator.size();
    }

    [[nodiscard]] auto body_size_cap(http::RequestLimits const& limits) noexcept -> std::size_t
    {
        return static_cast<std::size_t>(limits.max_body_bytes);
    }

    [[nodiscard]] auto recv_with_timeout(ConnectionStream& stream, char* buffer, std::size_t capacity) noexcept
        -> std::ptrdiff_t
    {
        auto entry = pollfd{};
        entry.fd = stream.fd();
        entry.events = POLLIN;
        auto const poll_result = ::poll(&entry, 1U, receive_timeout_milliseconds);
        if (poll_result <= 0)
        {
            return -1;
        }
        if ((entry.revents & POLLIN) == 0)
        {
            return -1;
        }
        return stream.read(buffer, capacity);
    }

    [[nodiscard]] auto read_request_head(ConnectionStream& stream, std::size_t cap)
        -> std::pair<std::string, std::size_t>
    {
        auto buffer = std::string{};
        auto chunk = std::array<char, 4096U>{};
        while (true)
        {
            if (buffer.size() >= cap)
            {
                return {std::move(buffer), std::string::npos};
            }
            auto const remaining_capacity = cap - buffer.size();
            auto const wanted = remaining_capacity < chunk.size() ? remaining_capacity : chunk.size();
            auto const received = recv_with_timeout(stream, chunk.data(), wanted);
            if (received <= 0)
            {
                return {std::move(buffer), std::string::npos};
            }
            buffer.append(chunk.data(), static_cast<std::size_t>(received));
            auto const terminator = buffer.find(header_terminator);
            if (terminator != std::string::npos)
            {
                return {std::move(buffer), terminator + header_terminator.size()};
            }
        }
    }

    [[nodiscard]] auto read_remaining_body(ConnectionStream& stream, std::string head_tail, std::size_t expected,
                                           std::size_t cap) -> std::string
    {
        if (expected > cap)
        {
            return {};
        }
        auto body = std::move(head_tail);
        if (body.size() >= expected)
        {
            body.resize(expected);
            return body;
        }
        auto chunk = std::array<char, 4096U>{};
        while (body.size() < expected)
        {
            auto const remaining = expected - body.size();
            auto const wanted = remaining < chunk.size() ? remaining : chunk.size();
            auto const received = recv_with_timeout(stream, chunk.data(), wanted);
            if (received <= 0)
            {
                return {};
            }
            body.append(chunk.data(), static_cast<std::size_t>(received));
        }
        return body;
    }

    [[nodiscard]] auto reason_phrase(std::uint16_t status) noexcept -> char const*
    {
        switch (status)
        {
        case 200U:
            return "OK";
        case 400U:
            return "Bad Request";
        case 401U:
            return "Unauthorized";
        case 403U:
            return "Forbidden";
        case 404U:
            return "Not Found";
        case 408U:
            return "Request Timeout";
        case 413U:
            return "Payload Too Large";
        case 429U:
            return "Too Many Requests";
        case 500U:
            return "Internal Server Error";
        case 501U:
            return "Not Implemented";
        case 502U:
            return "Bad Gateway";
        case 503U:
            return "Service Unavailable";
        default:
            return "OK";
        }
    }

    [[nodiscard]] auto format_response(std::uint16_t status, std::string_view body) -> std::string
    {
        auto response = std::string{};
        response.reserve(body.size() + 128U);
        response.append("HTTP/1.1 ");
        response.append(std::to_string(status));
        response.push_back(' ');
        response.append(reason_phrase(status));
        response.append("\r\nContent-Length: ");
        response.append(std::to_string(body.size()));
        response.append("\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
        response.append(body);
        return response;
    }

    auto send_all(ConnectionStream& stream, std::string_view data) noexcept -> bool
    {
        auto remaining = data;
        while (!remaining.empty())
        {
            auto const sent = stream.write(remaining);
            if (sent <= 0)
            {
                return false;
            }
            remaining.remove_prefix(static_cast<std::size_t>(sent));
        }
        return true;
    }

    [[nodiscard]] auto find_header_value(http::RequestHead const& head, std::string_view name) -> std::string
    {
        for (auto const& header : head.headers)
        {
            if (header.name.size() != name.size())
            {
                continue;
            }
            auto match = true;
            for (auto index = std::size_t{0U}; index < name.size(); ++index)
            {
                auto const left = header.name[index];
                auto const right = name[index];
                auto const left_lower = (left >= 'A' && left <= 'Z') ? static_cast<char>(left - 'A' + 'a') : left;
                auto const right_lower = (right >= 'A' && right <= 'Z') ? static_cast<char>(right - 'A' + 'a') : right;
                if (left_lower != right_lower)
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return header.value;
            }
        }
        return {};
    }

    [[nodiscard]] auto extract_bearer_token(std::string_view authorization) -> std::string
    {
        auto constexpr prefix = std::string_view{"Bearer "};
        if (authorization.size() <= prefix.size())
        {
            return std::string{authorization};
        }
        // Compare case-insensitively only on the scheme name.
        for (auto index = std::size_t{0U}; index < prefix.size(); ++index)
        {
            auto const candidate = authorization[index];
            auto const expected = prefix[index];
            auto const candidate_lower =
                (candidate >= 'A' && candidate <= 'Z') ? static_cast<char>(candidate - 'A' + 'a') : candidate;
            auto const expected_lower =
                (expected >= 'A' && expected <= 'Z') ? static_cast<char>(expected - 'A' + 'a') : expected;
            if (candidate_lower != expected_lower)
            {
                return std::string{authorization};
            }
        }
        return std::string{authorization.substr(prefix.size())};
    }

    [[nodiscard]] auto build_local_request(http::RequestHead const& head, std::string body) -> LocalHttpRequest
    {
        auto request = LocalHttpRequest{};
        request.method = head.method;
        request.target = head.target;
        request.body = std::move(body);
        auto const authorization = find_header_value(head, "authorization");
        if (!authorization.empty())
        {
            request.access_token = extract_bearer_token(authorization);
        }
        return request;
    }

    auto write_error_response(ConnectionStream& stream, std::uint16_t status, std::string_view body) noexcept -> void
    {
        auto const response = format_response(status, body);
        std::ignore = send_all(stream, response);
    }

    auto serve_stream(ConnectionStream& stream, ClientServerRuntime& runtime, std::mutex& runtime_lock,
                      HttpServeStats& stats, HttpDispatchMode dispatch_mode) -> void
    {
        auto const limits = http::RequestLimits{};
        auto const head_cap = header_size_cap(limits);
        auto [buffer, head_end] = read_request_head(stream, head_cap);

        if (head_end == std::string::npos)
        {
            {
                auto guard = std::lock_guard<std::mutex>{runtime_lock};
                ++stats.rejected_requests;
            }
            if (buffer.size() >= head_cap)
            {
                log_diagnostic("request.rejected", {
                                                       {"status",         "413",                         false},
                                                       {"received_bytes", std::to_string(buffer.size()), false},
                                                       {"limit_bytes",    std::to_string(head_cap),      false},
                                                       {"reason",         "request head too large",      false}
                });
                write_error_response(stream, 413U, "request head too large");
            }
            else
            {
                log_diagnostic("request.rejected", {
                                                       {"status",         "408",                                  false},
                                                       {"received_bytes", std::to_string(buffer.size()),          false},
                                                       {"reason",         "request head incomplete or timed out", false}
                });
                write_error_response(stream, 408U, "request head incomplete or timed out");
            }
            return;
        }

        auto const parse = http::parse_request_head(std::string_view{buffer.data(), head_end});
        if (parse.error != http::RequestErrorCode::none)
        {
            {
                auto guard = std::lock_guard<std::mutex>{runtime_lock};
                ++stats.rejected_requests;
            }
            auto reason = std::string{"request rejected: "};
            reason.append(http::request_error_name(parse.error));
            log_diagnostic("request.rejected",
                           {
                               {"status", std::to_string(http::request_error_status(parse.error)), false},
                               {"reason", http::request_error_name(parse.error),                   false}
            });
            write_error_response(stream, http::request_error_status(parse.error), reason);
            return;
        }

        auto body_tail = std::string{buffer.substr(head_end)};
        auto body = std::string{};
        if (parse.request.has_content_length && parse.request.content_length > 0U)
        {
            auto const expected = static_cast<std::size_t>(parse.request.content_length);
            body = read_remaining_body(stream, std::move(body_tail), expected, body_size_cap(limits));
            if (body.size() != expected)
            {
                {
                    auto guard = std::lock_guard<std::mutex>{runtime_lock};
                    ++stats.rejected_requests;
                }
                log_diagnostic("request.rejected",
                               {
                                   {"method",              parse.request.method,                                       false},
                                   {"target",              observability::sanitized_http_target(parse.request.target), false},
                                   {"status",              "408",                                                      false},
                                   {"expected_body_bytes", std::to_string(expected),                                   false},
                                   {"received_body_bytes", std::to_string(body.size()),                                false},
                                   {"reason",              "request body incomplete or timed out",                     false}
                });
                write_error_response(stream, 408U, "request body incomplete or timed out");
                return;
            }
        }

        auto const local_request = build_local_request(parse.request, std::move(body));
        log_diagnostic("request.dispatch",
                       {
                           {"method",           local_request.method,                                       false},
                           {"target",           observability::sanitized_http_target(local_request.target), false},
                           {"body_bytes",       std::to_string(local_request.body.size()),                  false},
                           {"has_access_token", local_request.access_token.empty() ? "false" : "true",      false}
        });

        auto response = LocalHttpResponse{};
        {
            auto guard = std::unique_lock<std::mutex>{runtime_lock};
            response = dispatch_local_http_request(runtime, local_request, dispatch_mode, &guard);
            ++stats.completed_requests;
        }

        log_diagnostic("request.completed",
                       {
                           {"method",         local_request.method,                                       false},
                           {"target",         observability::sanitized_http_target(local_request.target), false},
                           {"status",         std::to_string(response.status),                            false},
                           {"response_bytes", std::to_string(response.body.size()),                       false}
        });
        auto const formatted = format_response(response.status, response.body);
        std::ignore = send_all(stream, formatted);
    }

} // namespace

auto dispatch_local_http_request(ClientServerRuntime& runtime, LocalHttpRequest const& request, HttpDispatchMode mode,
                                  std::unique_lock<std::mutex>* dispatch_lock) -> LocalHttpResponse
{
    switch (mode)
    {
    case HttpDispatchMode::client_server:
        return handle_client_server_request(runtime, request, dispatch_lock);
    case HttpDispatchMode::federation:
        return handle_federation_http_request(runtime.homeserver, request);
    case HttpDispatchMode::local_router:
        return handle_local_http_request(runtime.homeserver, request);
    }

    return {500U, "unknown dispatch mode"};
}

auto serve_one_http_connection(int client_fd, ClientServerRuntime& runtime, std::mutex& runtime_lock,
                               HttpServeStats& stats, HttpDispatchMode dispatch_mode) -> void
{
    auto stream = PlainConnectionStream{client_fd};
    serve_stream(stream, runtime, runtime_lock, stats, dispatch_mode);
}

auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, std::mutex& runtime_lock,
                net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode) -> void
{
    while (!shutdown.fired() && acceptor.valid())
    {
        auto entries = std::array<pollfd, 2U>{};
        entries[0].fd = acceptor.fd();
        entries[0].events = POLLIN;
        entries[1].fd = shutdown.read_fd();
        entries[1].events = POLLIN;

        auto const poll_result = ::poll(entries.data(), entries.size(), -1);
        if (poll_result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return;
        }
        if ((entries[1].revents & POLLIN) != 0 || shutdown.fired())
        {
            return;
        }
        if ((entries[0].revents & POLLIN) == 0)
        {
            continue;
        }

        auto raw_client = ::accept(acceptor.fd(), nullptr, nullptr);
        if (raw_client < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            log_diagnostic("connection.accept_failed", {
                                                           {"errno", std::to_string(errno), false}
            });
            return;
        }
        auto client = core::SocketHandle{raw_client};
        {
            auto guard = std::lock_guard<std::mutex>{runtime_lock};
            ++stats.accepted_connections;
        }
        serve_one_http_connection(client.native_handle(), runtime, runtime_lock, stats, dispatch_mode);
        std::ignore = ::shutdown(client.native_handle(), SHUT_RDWR);
    }
}

auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    std::mutex& runtime_lock, net::ShutdownSignal& shutdown, HttpServeStats& stats,
                    HttpDispatchMode dispatch_mode) -> void
{
    while (!shutdown.fired() && acceptor.valid())
    {
        auto entries = std::array<pollfd, 2U>{};
        entries[0].fd = acceptor.fd();
        entries[0].events = POLLIN;
        entries[1].fd = shutdown.read_fd();
        entries[1].events = POLLIN;

        auto const poll_result = ::poll(entries.data(), entries.size(), -1);
        if (poll_result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return;
        }
        if ((entries[1].revents & POLLIN) != 0 || shutdown.fired())
        {
            return;
        }
        if ((entries[0].revents & POLLIN) == 0)
        {
            continue;
        }

        auto raw_client = ::accept(acceptor.fd(), nullptr, nullptr);
        if (raw_client < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            log_diagnostic("tls.connection.accept_failed", {
                                                               {"errno", std::to_string(errno), false}
            });
            return;
        }
        auto client = core::SocketHandle{raw_client};
        {
            auto guard = std::lock_guard<std::mutex>{runtime_lock};
            ++stats.accepted_connections;
        }

        auto accepted_tls = accept_tls_connection(tls_context, client.native_handle(), receive_timeout_milliseconds);
        if (!accepted_tls.ok())
        {
            auto guard = std::lock_guard<std::mutex>{runtime_lock};
            ++stats.rejected_requests;
            log_diagnostic("tls.handshake.rejected", {
                                                         {"reason", accepted_tls.error, false}
            });
            continue;
        }

        auto stream = TlsConnectionStream{*accepted_tls.connection};
        serve_stream(stream, runtime, runtime_lock, stats, dispatch_mode);
        std::ignore = ::shutdown(client.native_handle(), SHUT_RDWR);
    }
}

} // namespace merovingian::homeserver
