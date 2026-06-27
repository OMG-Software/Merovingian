// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/http_server.hpp"

#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/http/request_limits.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#if __has_include(<cxxabi.h>) && defined(__GNUC__)
#include <cxxabi.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("http_server", event, fields, severity);
    }

    // Convert the peer sockaddr captured at accept() time to a dotted-decimal
    // (IPv4) or colon-separated (IPv6) string. Returns an empty string when
    // the address family is unknown rather than crashing — the rate limiter
    // treats empty as "unknown" and falls back to the synthetic global bucket.
    [[nodiscard]] auto peer_addr_to_string(sockaddr_storage const& sa) noexcept -> std::string
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (sa.ss_family == AF_INET)
        {
            auto const* in4 = reinterpret_cast<sockaddr_in const*>(&sa);
            if (::inet_ntop(AF_INET, &in4->sin_addr, buf, sizeof(buf)) == nullptr)
            {
                return {};
            }
        }
        else if (sa.ss_family == AF_INET6)
        {
            auto const* in6 = reinterpret_cast<sockaddr_in6 const*>(&sa);
            if (::inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf)) == nullptr)
            {
                return {};
            }
        }
        return {buf};
    }

    // C2: the three swallowed-exception sites in this file (sync wait, sync
    // pool dispatch, dispatch_local_http_request) previously logged only
    // {"reason":"exception"}. Capture the mangled type and the std::exception
    // message so a postmortem can identify the throwing site. The mangled
    // name is intentionally not demangled here so the helper stays portable
    // across libstdc++ / libc++ / MSVC.
    [[nodiscard]] auto current_exception_type_name() noexcept -> char const*
    {
#if __has_include(<cxxabi.h>) && defined(__GNUC__)
        auto const* type = abi::__cxa_current_exception_type();
        return type == nullptr ? "unknown" : type->name();
#else
        return "unknown";
#endif
    }

    [[nodiscard]] auto current_exception_message() noexcept -> std::string
    {
        try
        {
            std::rethrow_exception(std::current_exception());
        }
        catch (std::exception const& ex)
        {
            return std::string{ex.what()};
        }
        catch (...)
        {
            return {};
        }
    }

    auto log_swallowed_exception(std::string_view site) -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{
            observability::StructuredLogField{"site", std::string{site},                          false},
            observability::StructuredLogField{"type", std::string{current_exception_type_name()}, false},
            observability::StructuredLogField{"what", current_exception_message(),                false}
        };
        log_diagnostic("sync.exception", std::move(fields));
    }

    // Conservative deadlines for the minimal serve loop. The slowloris policy
    // scaffolding in http/connection_guard.cpp will replace these once
    // connection-level accounting lands.
    constexpr auto receive_timeout_milliseconds = 15000;
    // B3: slowloris hardening. Two new caps layered on top of the per-byte
    // poll above:
    //   - overall request-head deadline (default 30 s): a slow client can
    //     dribble a head indefinitely without ever filling the head buffer
    //     or tripping the per-byte poll, so the worker would otherwise stay
    //     parked until head_cap bytes had been dribbled in.
    //   - per-byte inter-byte cap (default 5 s): a client that sends one
    //     byte per recv poll would otherwise still be inside the 15 s
    //     per-poll window; 5 s between bytes is a reasonable upper bound
    //     for any non-attack traffic.
    constexpr auto request_head_deadline = std::chrono::seconds{30};
    constexpr auto inter_byte_timeout = std::chrono::seconds{5};
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
        // Holds shared ownership of the TLS connection so that the read phase
        // (this thread) and the async write phase (sync-pool thread) can each
        // hold a reference without one dangling while the other is still running.
        // Constructed from a shared_ptr built via shared_ptr{std::move(unique_ptr)}
        // (not make_shared) to avoid GCC 16's spurious -Warray-bounds on the
        // _Sp_counted_ptr_inplace co-allocation destructor path.
        explicit TlsConnectionStream(
            std::shared_ptr<TlsConnection> connection) noexcept // SHARED_PTR: reviewed — read/write pool split
            : m_connection{std::move(connection)}
        {
        }

        [[nodiscard]] auto fd() const noexcept -> int override
        {
            return m_connection->fd();
        }

        [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t override
        {
            return m_connection->read(buffer, capacity);
        }

        [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t override
        {
            return m_connection->write(data);
        }

    private:
        std::shared_ptr<TlsConnection> m_connection; // SHARED_PTR: reviewed — shared by read and write pool threads
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
        auto const start = std::chrono::steady_clock::now();
        auto last_byte = start;
        while (true)
        {
            // B3 slowloris: enforce an overall deadline and an inter-byte cap
            // in addition to the per-byte recv poll timeout. The deadline
            // bounds the worst-case worker hold time regardless of how
            // cleverly the client dribbles bytes.
            auto const now = std::chrono::steady_clock::now();
            if (now - start > request_head_deadline)
            {
                log_diagnostic(
                    "request.head_slowloris",
                    {
                        {"reason",         "overall_deadline",                                                       false},
                        {"elapsed_ms",
                         std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count()),
                         false                                                                                            },
                        {"bytes_received", std::to_string(buffer.size()),                                            false}
                });
                return {std::move(buffer), std::string::npos};
            }
            if (now - last_byte > inter_byte_timeout)
            {
                log_diagnostic(
                    "request.head_slowloris",
                    {
                        {"reason",         "inter_byte_timeout",                                                         false},
                        {"elapsed_ms",
                         std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - last_byte).count()),
                         false                                                                                                },
                        {"bytes_received", std::to_string(buffer.size()),                                                false}
                });
                return {std::move(buffer), std::string::npos};
            }
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
            last_byte = std::chrono::steady_clock::now();
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

    [[nodiscard]] auto format_response(std::uint16_t status, std::string_view body,
                                       std::vector<std::pair<std::string, std::string>> const& headers = {})
        -> std::string
    {
        auto response = std::string{};
        response.reserve(body.size() + 128U + 256U * headers.size());
        response.append("HTTP/1.1 ");
        response.append(std::to_string(status));
        response.push_back(' ');
        response.append(reason_phrase(status));
        // Per-response headers (CORS preflight, Vary: Origin) come first so
        // the browser sees them before Content-Length/Content-Type. Defaulted
        // to empty for the few synthetic responses that carry no metadata.
        auto has_nosniff = false;
        auto content_type = std::string{"application/json"};
        for (auto const& header : headers)
        {
            if (!http::header_name_is_valid(header.first) || !http::header_value_is_valid(header.second))
            {
                continue;
            }
            if (header.first == "X-Content-Type-Options" && header.second == "nosniff")
            {
                has_nosniff = true;
            }
            if (header.first == "Content-Type")
            {
                content_type = header.second;
                continue;
            }
            response.append("\r\n");
            response.append(header.first);
            response.append(": ");
            response.append(header.second);
        }
        if (!has_nosniff)
        {
            response.append("\r\nX-Content-Type-Options: nosniff");
        }
        response.append("\r\nContent-Length: ");
        response.append(std::to_string(body.size()));
        if (content_type.empty())
        {
            content_type = "application/json";
        }
        response.append("\r\nContent-Type: ");
        response.append(content_type);
        response.append("\r\nConnection: close\r\n\r\n");
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

    [[nodiscard]] auto build_local_request(http::RequestHead const& head, std::string body, std::string_view peer_addr)
        -> LocalHttpRequest
    {
        auto request = LocalHttpRequest{};
        request.method = head.method;
        request.target = head.target;
        request.body = std::move(body);
        // Copy all request headers so downstream code (CORS, trusted-proxy
        // X-Forwarded-For resolution) has the full wire header set.
        request.headers = head.headers;
        auto const authorization = find_header_value(head, "authorization");
        if (!authorization.empty())
        {
            request.access_token = extract_bearer_token(authorization);
        }
        request.remote_addr = std::string{peer_addr};
        return request;
    }

    auto write_error_response(ConnectionStream& stream, std::uint16_t status, std::string_view body) noexcept -> void
    {
        auto const response = format_response(status, body);
        std::ignore = send_all(stream, response);
    }

    // Routes a request without ever blocking. The caller is responsible for
    // handling DispatchResult::Status::needs_wait (long-poll sync).
    [[nodiscard]] auto route_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                     HttpDispatchMode mode) -> DispatchResult
    {
        // Fast path: the key-server endpoint is served from a lock-free atomic
        // cache so concurrent federation makes-join cannot delay it.
        if (mode == HttpDispatchMode::federation && request.method == "GET" &&
            request.target == "/_matrix/key/v2/server")
        {
            auto& cache = runtime.homeserver.database.key_server_cache;
            if (cache)
            {
                if (auto cached = cache->load())
                {
                    return {
                        DispatchResult::Status::complete, {200U, *cached},
                         {}
                    };
                }
            }
        }
        auto result = DispatchResult{};
        switch (mode)
        {
        case HttpDispatchMode::client_server:
            result = handle_client_server_request(runtime, request);
            break;
        case HttpDispatchMode::federation:
            if (runtime.homeserver.federation_proxy != nullptr)
            {
                result.response = runtime.homeserver.federation_proxy->handle(request);
            }
            else
            {
                result.response = handle_federation_http_request(runtime.homeserver, request);
            }
            break;
        case HttpDispatchMode::local_router:
            result.response = handle_local_http_request(runtime.homeserver, request);
            break;
        }
        return result;
    }

    // Returns true when the fd has been transferred to sync_pool (caller must
    // NOT shut down or close it). Returns false in all other cases — the caller
    // retains ownership of the fd.
    //
    // async_write_fn: if non-null, the sync-pool lambda calls this instead of
    // ::send(fd,…) to write the response. Used by the TLS path to route the
    // write through the OpenSSL layer rather than the raw file descriptor.
    [[nodiscard]] auto serve_stream(ConnectionStream& stream, ClientServerRuntime& runtime, HttpServeStats& stats,
                                    HttpDispatchMode dispatch_mode, net::ThreadPool* sync_pool,
                                    std::string_view peer_addr = {},
                                    std::function<std::ptrdiff_t(std::string_view)> async_write_fn = {}) -> bool
    {
        auto const limits = http::RequestLimits{};
        auto const head_cap = header_size_cap(limits);
        auto [buffer, head_end] = read_request_head(stream, head_cap);

        if (head_end == std::string::npos)
        {
            ++stats.rejected_requests;
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
            return false;
        }

        auto const parse = http::parse_request_head(std::string_view{buffer.data(), head_end});
        if (parse.error != http::RequestErrorCode::none)
        {
            ++stats.rejected_requests;
            auto reason = std::string{"request rejected: "};
            reason.append(http::request_error_name(parse.error));
            log_diagnostic("request.rejected",
                           {
                               {"status", std::to_string(http::request_error_status(parse.error)), false},
                               {"reason", http::request_error_name(parse.error),                   false}
            });
            write_error_response(stream, http::request_error_status(parse.error), reason);
            return false;
        }

        auto body_tail = std::string{buffer.substr(head_end)};
        auto body = std::string{};
        if (parse.request.has_content_length && parse.request.content_length > 0U)
        {
            auto const expected = static_cast<std::size_t>(parse.request.content_length);
            // Media upload routes permit up to max_upload_size; every other
            // client-server route uses the smaller general body cap.
            auto const effective_cap = [&]() -> std::size_t {
                if (dispatch_mode == HttpDispatchMode::client_server && parse.request.method == "POST")
                {
                    auto const& t = parse.request.target;
                    auto const is_media =
                        (t == "/_matrix/media/v3/upload" || t.starts_with("/_matrix/media/v3/upload?") ||
                         t == "/_matrix/client/v1/media/upload" || t.starts_with("/_matrix/client/v1/media/upload?"));
                    if (is_media)
                    {
                        auto const parsed =
                            config::parse_size_limit(runtime.homeserver.config.security().media.max_upload_size);
                        auto const raw = parsed.valid ? parsed.bytes : std::uint64_t{104857600U};
                        return raw > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                             : static_cast<std::size_t>(raw);
                    }
                }
                return body_size_cap(limits);
            }();
            if (expected > effective_cap)
            {
                ++stats.rejected_requests;
                log_diagnostic("request.rejected",
                               {
                                   {"method",              parse.request.method,                                       false},
                                   {"target",              observability::sanitized_http_target(parse.request.target), false},
                                   {"status",              "413",                                                      false},
                                   {"expected_body_bytes", std::to_string(expected),                                   false},
                                   {"limit_bytes",         std::to_string(effective_cap),                              false},
                                   {"reason",              "request body too large",                                   false}
                });
                // Matrix spec §10.5: every response MUST carry CORS headers or
                // browsers surface the 413 as a CORS error instead of the real one.
                auto cors_hdrs = std::vector<std::pair<std::string, std::string>>{};
                if (dispatch_mode == HttpDispatchMode::client_server && !runtime.cors.allowed_origins.empty())
                {
                    auto const origin = find_header_value(parse.request, "origin");
                    if (!origin.empty())
                    {
                        for (auto const& allowed : runtime.cors.allowed_origins)
                        {
                            if (allowed == "*" || allowed == origin)
                            {
                                cors_hdrs.emplace_back("Access-Control-Allow-Origin",
                                                       allowed == "*" ? std::string{"*"} : std::string{origin});
                                break;
                            }
                        }
                    }
                }
                auto const rejection =
                    format_response(413U, R"({"errcode":"M_TOO_LARGE","error":"request body too large"})", cors_hdrs);
                std::ignore = send_all(stream, rejection);
                return false;
            }
            body = read_remaining_body(stream, std::move(body_tail), expected, effective_cap);
            if (body.size() != expected)
            {
                ++stats.rejected_requests;
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
                return false;
            }
        }

        auto const local_request = build_local_request(parse.request, std::move(body), peer_addr);
        log_diagnostic("request.dispatch",
                       {
                           {"method",           local_request.method,                                       false},
                           {"target",           observability::sanitized_http_target(local_request.target), false},
                           {"body_bytes",       std::to_string(local_request.body.size()),                  false},
                           {"has_access_token", local_request.access_token.empty() ? "false" : "true",      false}
        });

        auto result = route_request(runtime, local_request, dispatch_mode);

        if (result.status == DispatchResult::Status::needs_wait)
        {
            auto* notifier = runtime.sync_notifier.get();
            if (notifier == nullptr)
            {
                write_error_response(stream, 503U, matrix_error("M_UNKNOWN", "sync notifier unavailable"));
                return false;
            }

            if (sync_pool != nullptr)
            {
                // Hand off to the dedicated sync pool. The current main-pool thread
                // is freed immediately. The sync pool thread owns the fd exclusively
                // from this point and must close it when done.
                //
                // Poll in 5-second slices so that server shutdown (sync_pool.request_stop())
                // is bounded to at most one slice even when clients request long timeouts.
                // Clients re-poll immediately after an empty 200, so the slicing is transparent.
                auto const fd = stream.fd();
                auto const wait = result.wait;
                // async_write_fn is moved into the lambda so that TLS connections
                // write through the OpenSSL layer rather than via raw ::send().
                // For plain HTTP the function is null and ::send() is used directly.
                auto submitted = sync_pool->submit([fd, write_fn = std::move(async_write_fn), &runtime, &stats,
                                                    request_copy = local_request, wait, notifier, sync_pool]() mutable {
                    // Re-wait loop: after each notifier fire, call the handler with
                    // can_wait=true.  If the handler returns needs_wait the wakeup was
                    // caused by an event irrelevant to this connection (e.g. another
                    // user's device key upload); advance wait_params past the irrelevant
                    // bump and continue polling.  If it returns complete, send immediately.
                    // `wait` is captured const from the outer scope; use wait_params for
                    // the mutable cursor that tracks the advancing since-values.
                    auto dispatched_result = std::optional<DispatchResult>{};
                    auto client_gone = false;
                    try
                    {
                        // Poll in 1-second slices: short enough to detect a dropped
                        // client connection within one slice, yet not so short that
                        // it generates excessive wakeups.  Shutdown (request_stop())
                        // is bounded to one slice (≤1 s) regardless of client timeout.
                        constexpr auto poll_interval = std::chrono::milliseconds{1000U};
                        auto wait_params = wait; // mutable cursor
                        auto const deadline = std::chrono::steady_clock::now() + wait_params.timeout;
                        while (sync_pool->running())
                        {
                            auto const remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                deadline - std::chrono::steady_clock::now());
                            if (remaining.count() <= 0)
                            {
                                break;
                            }
                            if (notifier->wait_for_change(wait_params.since_stream_ordering,
                                                          wait_params.since_sync_stream_id,
                                                          std::min(remaining, poll_interval)))
                            {
                                auto interim = handle_client_server_request(runtime, request_copy, true);
                                if (interim.status == DispatchResult::Status::complete)
                                {
                                    dispatched_result = std::move(interim);
                                    break;
                                }
                                wait_params = interim.wait;
                            }
                            else
                            {
                                // Notifier did not fire (poll-slice timeout).  Check whether
                                // the TCP peer is still connected via a non-blocking peek.
                                // When the client closes (FIN or RST), recv returns 0 or a
                                // connection error — not EAGAIN — so the thread exits
                                // immediately instead of waiting for the next slice.  This
                                // prevents sync-pool exhaustion when clients reconnect
                                // rapidly (e.g. an SDK reset loop sends a new timeout=30000
                                // every ~90 ms while abandoning the previous one).
                                auto peek_buf = std::array<char, 1>{};
                                auto const n = ::recv(fd, peek_buf.data(), 1U, MSG_PEEK | MSG_DONTWAIT);
                                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                                {
                                    client_gone = true;
                                    break;
                                }
                            }
                        }
                    }
                    catch (...)
                    {
                        log_swallowed_exception("sync_pool_dispatch");
                    }
                    if (client_gone)
                    {
                        // Client closed before we could respond; release the fd and
                        // return the thread to the pool without logging a completed request.
                        ::close(fd);
                        return;
                    }
                    auto const final_result = dispatched_result.has_value()
                                                  ? std::move(*dispatched_result)
                                                  : handle_client_server_request(runtime, request_copy, false);
                    ++stats.completed_requests;
                    log_diagnostic("request.completed",
                                   {
                                       {"method",         request_copy.method,                                       false},
                                       {"target",         observability::sanitized_http_target(request_copy.target), false},
                                       {"status",         std::to_string(final_result.response.status),              false},
                                       {"response_bytes", std::to_string(final_result.response.body.size()),         false}
                    });
                    auto const formatted = format_response(final_result.response.status, final_result.response.body,
                                                           final_result.response.headers);
                    if (write_fn)
                    {
                        std::ignore = write_fn(formatted);
                    }
                    else
                    {
                        std::ignore = ::send(fd, formatted.data(), formatted.size(), MSG_NOSIGNAL);
                    }
                    std::ignore = ::shutdown(fd, SHUT_RDWR);
                    ::close(fd);
                });
                if (submitted)
                {
                    return true; // fd is now owned by the sync pool thread
                }
                // Sync pool is stopping; fall through to synchronous wait.
                // async_write_fn was moved-from into the rejected lambda; the sync
                // fallback path below uses stream.write() directly so that is fine.
            }

            // No sync_pool supplied (tests, pool shutting down): block this thread
            // until new events arrive or the timeout expires.
            // TLS connections use serve_tls_http which passes a sync_pool and
            // async_write_fn; they only reach this path if the pool is stopping.
            // Re-wait loop mirrors the sync_pool path: after each notifier fire,
            // call the handler with can_wait=true so it can park again when the
            // wakeup was not relevant to this connection.
            {
                auto wait = result.wait;
                auto deadline = std::chrono::steady_clock::now() + wait.timeout;
                auto dispatched = false;
                try
                {
                    while (!dispatched)
                    {
                        auto const remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now());
                        if (remaining.count() <= 0)
                        {
                            break;
                        }
                        if (notifier->wait_for_change(wait.since_stream_ordering, wait.since_sync_stream_id, remaining))
                        {
                            auto interim = handle_client_server_request(runtime, local_request, true);
                            if (interim.status == DispatchResult::Status::complete)
                            {
                                result = std::move(interim);
                                dispatched = true;
                            }
                            else
                            {
                                wait = interim.wait;
                            }
                        }
                        else
                        {
                            break; // timeout
                        }
                    }
                }
                catch (...)
                {
                    log_swallowed_exception("serve_stream_sync_wait");
                }
                if (!dispatched)
                {
                    result = handle_client_server_request(runtime, local_request, false);
                }
            }
        }

        ++stats.completed_requests;
        log_diagnostic("request.completed",
                       {
                           {"method",         local_request.method,                                       false},
                           {"target",         observability::sanitized_http_target(local_request.target), false},
                           {"status",         std::to_string(result.response.status),                     false},
                           {"response_bytes", std::to_string(result.response.body.size()),                false}
        });
        auto const formatted = format_response(result.response.status, result.response.body, result.response.headers);
        std::ignore = send_all(stream, formatted);
        return false;
    }

} // namespace

auto dispatch_local_http_request(ClientServerRuntime& runtime, LocalHttpRequest const& request, HttpDispatchMode mode)
    -> LocalHttpResponse
{
    // This public API preserves its original blocking behaviour for backward
    // compatibility (tests, one-off callers). The server's hot path uses
    // route_request() + serve_stream() with a dedicated sync_pool instead.
    auto result = route_request(runtime, request, mode);

    if (result.status == DispatchResult::Status::needs_wait)
    {
        auto* notifier = runtime.sync_notifier.get();
        if (notifier == nullptr)
        {
            return {503U, matrix_error("M_UNKNOWN", "sync notifier unavailable")};
        }
        // Re-wait loop: after each notifier fire, call the handler with can_wait=true
        // so sliding_sync_json can return needs_wait again when the wakeup was caused
        // by an event not relevant to this connection (e.g. another user uploading
        // device keys).  The handler advances wait.since_sync_stream_id past the
        // irrelevant bump, preventing an immediate re-fire.
        auto wait = result.wait;
        auto deadline = std::chrono::steady_clock::now() + wait.timeout;
        auto dispatched = false;
        try
        {
            while (!dispatched)
            {
                auto const remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
                if (remaining.count() <= 0)
                {
                    break;
                }
                if (notifier->wait_for_change(wait.since_stream_ordering, wait.since_sync_stream_id, remaining))
                {
                    auto interim = handle_client_server_request(runtime, request, true);
                    if (interim.status == DispatchResult::Status::complete)
                    {
                        result = std::move(interim);
                        dispatched = true;
                    }
                    else
                    {
                        wait = interim.wait;
                    }
                }
                else
                {
                    break; // timeout
                }
            }
        }
        catch (...)
        {
            log_swallowed_exception("dispatch_local_http_request");
        }
        if (!dispatched)
        {
            result = handle_client_server_request(runtime, request, false);
        }
    }

    return result.response;
}

auto serve_one_http_connection(int client_fd, ClientServerRuntime& runtime, HttpServeStats& stats,
                               HttpDispatchMode dispatch_mode, net::ThreadPool* sync_pool, std::string_view peer_addr)
    -> bool
{
    auto stream = PlainConnectionStream{client_fd};
    return serve_stream(stream, runtime, stats, dispatch_mode, sync_pool, peer_addr);
}

auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, net::ShutdownSignal& shutdown,
                HttpServeStats& stats, HttpDispatchMode dispatch_mode, net::ThreadPool& pool,
                net::ThreadPool* sync_pool) -> void
{
    while (!shutdown.fired() && acceptor.valid() && pool.running())
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

        sockaddr_storage peer_sa{};
        socklen_t peer_len = sizeof(peer_sa);
        auto raw_client = ::accept(acceptor.fd(), reinterpret_cast<sockaddr*>(&peer_sa), &peer_len);
        if (raw_client < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            // Transient resource exhaustion — retry after a brief pause
            // rather than permanently killing the listener thread.
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM)
            {
                log_diagnostic("connection.accept_retry", {
                                                              {"errno", std::to_string(errno), false}
                });
                ::usleep(100000);
                continue;
            }
            log_diagnostic("connection.accept_failed", {
                                                           {"errno", std::to_string(errno), false}
            });
            return;
        }
        auto peer_addr = peer_addr_to_string(peer_sa);
        // Release from SocketHandle so the fd ownership transfers into the
        // pool lambda. If the pool is stopping, submit returns false and we
        // close the fd immediately. Inside the lambda the fd is wrapped in a
        // SocketHandle for RAII so it is closed even on exceptions.
        auto client = core::SocketHandle{raw_client};
        auto fd = client.release();
        auto submitted =
            pool.submit([&runtime, &stats, dispatch_mode, sync_pool, fd, peer_addr = std::move(peer_addr)] {
                auto guard = core::SocketHandle{fd};
                ++stats.accepted_connections;
                auto const handed_off =
                    serve_one_http_connection(fd, runtime, stats, dispatch_mode, sync_pool, peer_addr);
                if (handed_off)
                {
                    // The sync pool thread owns the fd; do NOT shut it down here.
                    std::ignore = guard.release();
                }
                else
                {
                    std::ignore = ::shutdown(fd, SHUT_RDWR);
                    // ~SocketHandle closes fd on both normal and exceptional exit.
                }
            });
        if (!submitted)
        {
            // Pool is stopped — close the fd that nobody will handle.
            std::ignore = ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
    }
}

auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode,
                    net::ThreadPool& pool, net::ThreadPool* sync_pool) -> void
{
    while (!shutdown.fired() && acceptor.valid() && pool.running())
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

        sockaddr_storage tls_peer_sa{};
        socklen_t tls_peer_len = sizeof(tls_peer_sa);
        auto raw_client = ::accept(acceptor.fd(), reinterpret_cast<sockaddr*>(&tls_peer_sa), &tls_peer_len);
        if (raw_client < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM)
            {
                log_diagnostic("tls.connection.accept_retry", {
                                                                  {"errno", std::to_string(errno), false}
                });
                ::usleep(100000);
                continue;
            }
            log_diagnostic("tls.connection.accept_failed", {
                                                               {"errno", std::to_string(errno), false}
            });
            return;
        }
        auto tls_peer_addr = peer_addr_to_string(tls_peer_sa);
        // Release from SocketHandle so the fd ownership transfers into the
        // pool lambda. If the pool is stopping, submit returns false and we
        // close the fd immediately. Inside the lambda the fd is wrapped in a
        // SocketHandle for RAII so it is closed even on exceptions.
        auto client = core::SocketHandle{raw_client};
        auto fd = client.release();
        auto submitted = pool.submit(
            [&tls_context, &runtime, &stats, dispatch_mode, sync_pool, fd, tls_peer_addr = std::move(tls_peer_addr)] {
                auto guard = core::SocketHandle{fd};
                ++stats.accepted_connections;
                auto accepted_tls = accept_tls_connection(tls_context, fd, receive_timeout_milliseconds);
                if (!accepted_tls.ok())
                {
                    ++stats.rejected_requests;
                    log_diagnostic("tls.handshake.rejected", {
                                                                 {"reason", accepted_tls.error, false}
                    });
                    std::ignore = ::shutdown(fd, SHUT_RDWR);
                    return;
                    // ~SocketHandle closes fd on both normal and exceptional exit.
                }

                // Build shared ownership via unique_ptr → shared_ptr conversion.
                // Using shared_ptr{std::move(unique_ptr)} (not make_shared) allocates
                // the control block separately (_Sp_counted_deleter), avoiding the
                // GCC 16 -Warray-bounds false positive that fires when make_shared's
                // _Sp_counted_ptr_inplace co-allocation is inlined. Both TlsConnectionStream
                // (read phase, this thread) and the async_write_fn lambda (write phase,
                // sync-pool thread) hold a copy; the last one to finish cleans up.
                auto tls_unique = std::make_unique<TlsConnection>(std::move(*accepted_tls.connection));
                auto tls_shared = std::shared_ptr<TlsConnection>{// SHARED_PTR: reviewed — cross-thread TLS ownership
                                                                 std::move(tls_unique)};
                auto stream = TlsConnectionStream{tls_shared};

                auto async_write_fn =
                    std::function<std::ptrdiff_t(std::string_view)>{[tls = tls_shared](std::string_view data) {
                        return tls->write(data);
                    }};

                auto const transferred = serve_stream(stream, runtime, stats, dispatch_mode, sync_pool, tls_peer_addr,
                                                      std::move(async_write_fn));
                if (transferred)
                {
                    // The sync-pool thread now owns fd and holds tls_shared.
                    // Release the guard so the fd is not closed on this thread.
                    std::ignore = guard.release();
                }
                else
                {
                    std::ignore = ::shutdown(fd, SHUT_RDWR);
                    // ~guard closes fd; ~tls_shared frees the TLS connection.
                }
            });
        if (!submitted)
        {
            std::ignore = ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
    }
}

} // namespace merovingian::homeserver
