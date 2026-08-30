// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/http_server.hpp"

#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/connection_guard.hpp"
#include "merovingian/http/keep_alive.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/http/request_limits.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <atomic>
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
#include <optional>
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

    // Loop on ::send() until the whole buffer is written or a non-recoverable
    // error occurs.  This matches the TLS path's behaviour: a short write on a
    // non-blocking socket is retried rather than silently truncated.
    [[nodiscard]] auto send_all(int fd, std::string_view data) noexcept -> bool
    {
        auto const* ptr = data.data();
        auto remaining = data.size();
        while (remaining > 0U)
        {
            auto const n = ::send(fd, ptr, remaining, MSG_NOSIGNAL);
            if (n < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return false;
            }
            if (n == 0)
            {
                return false;
            }
            ptr += static_cast<std::size_t>(n);
            remaining -= static_cast<std::size_t>(n);
        }
        return true;
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

    // ---------------------------------------------------------------------
    // HTTP/1.1 persistent connections (keep-alive)
    //
    // Matrix v1.19 is served over HTTP/1.1, where persistent connections are
    // the default (RFC 9112 §9.3). A connection is served request-by-request
    // in a sequential loop: read one request, drain its body exactly, write
    // one response, then park the connection for the next request. Pipelining
    // (more than one outstanding request) is NOT supported: pipelined bytes
    // are buffered and served in order, one response at a time.
    // ---------------------------------------------------------------------

    // Everything a connection-serving task needs. `runtime` and `stats`
    // outlive every pool task (main.cpp stops the pools before the runtime
    // is torn down). `owner_pool` is the pool whose worker runs this
    // connection's loop — used to bound shutdown latency while parked.
    struct ConnectionContext final
    {
        ClientServerRuntime& runtime;
        HttpServeStats& stats;
        HttpDispatchMode dispatch_mode;
        net::ThreadPool* sync_pool;  // may be null (tests, no long-poll offload)
        net::ThreadPool* owner_pool; // may be null (direct serve_one calls)
        std::string peer_addr;
    };

    enum class ServeOutcome : std::uint8_t
    {
        // The connection is finished. The caller owns the fd and must shut it
        // down and close it.
        connection_closed,
        // A sync-pool long-poll task (or the keep-alive continuation it
        // submits) now owns the fd; the caller must NOT close it.
        transferred,
    };

    enum class RoundOutcome : std::uint8_t
    {
        // One request round finished and the connection must close.
        close_connection,
        // One request round finished with Connection: keep-alive; the caller
        // parks the connection and reads the next request.
        continue_keep_alive,
        // The request was a long-poll handed off to the sync pool (which
        // hands the connection back to owner_pool for the next request when
        // the client asked for keep-alive).
        transferred,
    };

    enum class NextRequestWait : std::uint8_t
    {
        // Bytes of the next request head arrived; read it.
        data_ready,
        // The keep-alive idle window passed with no next request.
        idle_expired,
        // The peer is gone or the pool is stopping; close without a response.
        connection_dead,
    };

    // Process-wide count of connections parked waiting for a subsequent
    // keep-alive request. All listeners share one main request pool, so the
    // cap must be process-wide too: a parked connection occupies a main-pool
    // worker thread, and without a cap a client could park one worker per
    // connection and stall every new request until each idle window expired.
    std::atomic<std::uint32_t> parked_keep_alive_connections{0U};

    // RAII handle for one acquired parking slot. The count is only held
    // while the connection is parked (idle, no request in flight); it is
    // released as soon as the next request's bytes arrive, so the cap bounds
    // parked threads, not active requests.
    class ParkedKeepAliveSlot final
    {
    public:
        ParkedKeepAliveSlot(ParkedKeepAliveSlot const&) = delete;
        auto operator=(ParkedKeepAliveSlot const&) -> ParkedKeepAliveSlot& = delete;
        ParkedKeepAliveSlot(ParkedKeepAliveSlot&& other) noexcept
            : m_held{std::exchange(other.m_held, false)}
        {
        }
        auto operator=(ParkedKeepAliveSlot&& other) noexcept -> ParkedKeepAliveSlot&
        {
            if (this != &other)
            {
                release();
                m_held = std::exchange(other.m_held, false);
            }
            return *this;
        }
        ~ParkedKeepAliveSlot()
        {
            release();
        }

        // Acquires one parking slot when the operator cap allows it, so the
        // number of parked connections stays bounded; nullopt means the cap
        // is reached and the connection must be closed instead of parked.
        [[nodiscard]] static auto try_acquire(http::KeepAlivePolicy const& policy) noexcept
            -> std::optional<ParkedKeepAliveSlot>
        {
            auto current = parked_keep_alive_connections.load(std::memory_order_relaxed);
            while (current < policy.max_connections)
            {
                if (parked_keep_alive_connections.compare_exchange_weak(
                        current, current + 1U, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    return ParkedKeepAliveSlot{ConstructTag{}};
                }
            }
            return std::nullopt;
        }

    private:
        struct ConstructTag final
        {
        };
        explicit ParkedKeepAliveSlot(ConstructTag) noexcept
        {
        }
        auto release() noexcept -> void
        {
            if (m_held)
            {
                m_held = false;
                parked_keep_alive_connections.fetch_sub(1U, std::memory_order_relaxed);
            }
        }
        bool m_held{true};
    };

    // The effective keep-alive policy for one connection. Parking is disabled
    // when there is no owning pool: direct serve_one_http_connection callers
    // (tests) keep the one-request-per-call contract, and a sync-pool
    // long-poll would have nowhere to hand the connection back to.
    [[nodiscard]] auto keep_alive_policy_for(ConnectionContext const& ctx) noexcept -> http::KeepAlivePolicy
    {
        auto const& http_config = ctx.runtime.homeserver.config.server().http;
        auto const enabled = http_config.keep_alive && ctx.owner_pool != nullptr;
        return {enabled, http_config.keep_alive_idle_seconds, http_config.keep_alive_max_connections};
    }

    [[nodiscard]] auto make_connection_stream(
        int fd,
        std::shared_ptr<TlsConnection> tls) // SHARED_PTR: reviewed — read/write pool split
        -> std::unique_ptr<ConnectionStream>
    {
        if (tls != nullptr)
        {
            return std::make_unique<TlsConnectionStream>(std::move(tls));
        }
        return std::make_unique<PlainConnectionStream>(fd);
    }

    // The sync-pool write callback for one round: routes writes through the
    // OpenSSL layer for TLS connections, raw ::send() for plain ones.
    [[nodiscard]] auto make_async_write_fn(
        std::shared_ptr<TlsConnection> const& tls) // SHARED_PTR: reviewed — sync-pool task outlives the round
        -> std::function<std::ptrdiff_t(std::string_view)>
    {
        if (tls == nullptr)
        {
            return {};
        }
        return std::function<std::ptrdiff_t(std::string_view)>{[tls](std::string_view data) {
            return tls->write(data);
        }};
    }

    // Parks a kept-alive connection until the next request head starts
    // arriving. Bounded by the keep-alive idle window (NOT by the slowloris
    // policy — a quiet connection is not a slow client; see
    // http::connection_should_close) and polls in one-second slices so a
    // pool request_stop() is bounded to at most one slice regardless of the
    // configured window.
    [[nodiscard]] auto wait_for_next_request(ConnectionStream& stream, net::ThreadPool const* owner_pool,
                                             http::KeepAlivePolicy const& policy) -> NextRequestWait
    {
        auto const slowloris = http::SlowlorisPolicy{};
        auto const start = std::chrono::steady_clock::now();
        while (true)
        {
            if (owner_pool != nullptr && !owner_pool->running())
            {
                return NextRequestWait::connection_dead;
            }
            auto const elapsed = std::chrono::steady_clock::now() - start;
            auto const elapsed_seconds =
                static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
            // Phase-aware guard composition: awaiting_request is bounded only
            // by the idle window. The slowloris policy still applies in full
            // to the request head read that follows once bytes arrive.
            if (http::connection_should_close(http::ConnectionPhase::awaiting_request,
                                              http::RequestProgress{0U, elapsed_seconds}, slowloris, policy))
            {
                return NextRequestWait::idle_expired;
            }
            auto const idle_remaining = std::chrono::seconds{policy.idle_timeout_seconds} - elapsed;
            // Sub-second remainder guard: the integer-second deadline above
            // still reads `elapsed_seconds == idle` while the true window is
            // already spent (e.g. 1.005 s into a 1 s window). Slicing that
            // negative remainder into poll() would be treated by Linux as
            // "block indefinitely" (any negative timeout is infinite), so a
            // parked connection would never wake to expire. Treat a spent
            // window as expired instead.
            if (idle_remaining <= std::chrono::seconds{0})
            {
                return NextRequestWait::idle_expired;
            }
            auto const slice =
                idle_remaining < std::chrono::milliseconds{1000U} ? idle_remaining : std::chrono::milliseconds{1000U};
            auto entry = pollfd{};
            entry.fd = stream.fd();
            entry.events = POLLIN;
            auto const poll_result = ::poll(
                &entry, 1U, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(slice).count()));
            if (poll_result < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return NextRequestWait::connection_dead;
            }
            if (poll_result > 0)
            {
                if ((entry.revents & POLLIN) != 0)
                {
                    return NextRequestWait::data_ready;
                }
                return NextRequestWait::connection_dead;
            }
            // Slice elapsed: re-evaluate the idle deadline and stop flag.
        }
    }

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

    // Reads one full request head. `buffered` carries bytes read past the
    // previous request (pipelined next request) so request boundaries are
    // never lost across keep-alive rounds; a complete head already in it is
    // returned without touching the socket. The slowloris clocks restart per
    // call, i.e. per request — a keep-alive connection parked between
    // requests is not charged for its idle time.
    [[nodiscard]] auto read_request_head(ConnectionStream& stream, std::string buffered, std::size_t cap)
        -> std::pair<std::string, std::size_t>
    {
        auto buffer = std::move(buffered);
        // Pipelined head already fully buffered: no recv needed. This check
        // must precede the deadline logic so an idle park followed by a
        // buffered head is not misread as a slow client.
        if (auto const buffered_terminator = buffer.find(header_terminator); buffered_terminator != std::string::npos)
        {
            return {std::move(buffer), buffered_terminator + header_terminator.size()};
        }
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

    // Body-read outcome. `leftover` holds any bytes past the request's
    // Content-Length that already arrived (a pipelined next request); they
    // are preserved so the keep-alive loop never loses a request boundary.
    struct BodyReadResult final
    {
        std::string body{};
        std::string leftover{};
        bool complete{false};
    };

    [[nodiscard]] auto read_remaining_body(ConnectionStream& stream, std::string head_tail, std::size_t expected,
                                           std::size_t cap) -> BodyReadResult
    {
        if (expected > cap)
        {
            return {};
        }
        auto body = std::move(head_tail);
        if (body.size() >= expected)
        {
            auto leftover = body.substr(expected);
            body.resize(expected);
            return {std::move(body), std::move(leftover), true};
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
        return {std::move(body), {}, true};
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

    // Formats a full HTTP/1.1 response. `connection` selects the framing
    // declaration: keep_alive announces a persistent connection and adds the
    // Keep-Alive timeout hint so clients know how long the server will hold
    // the connection idle (RFC 9110 §7.6.1 connection tokens; the hint header
    // itself is non-standard but universally understood). Error responses and
    // every path that keeps today's one-request-per-connection behaviour use
    // the default `close`.
    [[nodiscard]] auto format_response(std::uint16_t status, std::string_view body,
                                       std::vector<std::pair<std::string, std::string>> const& headers = {},
                                       http::ConnectionPreference connection = http::ConnectionPreference::close,
                                       std::uint32_t keep_alive_timeout_seconds = 0U) -> std::string
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
        if (connection == http::ConnectionPreference::keep_alive)
        {
            response.append("\r\nConnection: keep-alive");
            // Hint, not a promise: the server still closes early when the
            // parked-connection cap is reached or shutdown begins.
            response.append("\r\nKeep-Alive: timeout=");
            response.append(std::to_string(keep_alive_timeout_seconds));
        }
        else
        {
            response.append("\r\nConnection: close");
        }
        response.append("\r\n\r\n");
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
                auto const now_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                   std::chrono::system_clock::now().time_since_epoch())
                                                                   .count());
                // A stale document falls through to the slow path, which re-publishes
                // it with a fresh valid_until_ts before serving.
                if (auto cached = cache->load(now_ms))
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

    // Serves exactly one request round: read the head, drain the body exactly,
    // route, write one response. `leftover` carries pipelined bytes in and, on
    // keep-alive rounds, the bytes past this request's body back out so the
    // next round never loses a request boundary. `first_request` marks the
    // connection's opening round: a later round whose head read gets zero
    // bytes is a client closing an idle parked connection and is closed
    // silently rather than answered with a 408.
    //
    // Returns close_connection / continue_keep_alive, or transferred when a
    // long-poll was handed off to the sync pool: the sync task then owns the
    // fd (the caller must NOT close it) and, when the client asked for
    // keep-alive, re-submits the connection to ctx.owner_pool for its next
    // round.
    [[nodiscard]] auto serve_connection(
        int fd,
        std::shared_ptr<TlsConnection> tls, // SHARED_PTR: reviewed — read/write pool split
        ConnectionContext& ctx) -> ServeOutcome;

    [[nodiscard]] auto serve_request_round(
        ConnectionStream& stream,
        std::shared_ptr<TlsConnection> tls, // SHARED_PTR: reviewed — sync-pool task outlives the round
        ConnectionContext& ctx, std::string& leftover, bool first_request) -> RoundOutcome
    {
        auto const limits = http::RequestLimits{};
        auto const head_cap = header_size_cap(limits);
        auto [buffer, head_end] = read_request_head(stream, std::move(leftover), head_cap);
        // std::move(leftover) leaves it valid-but-unspecified; reset it. It is
        // re-assigned below with this round's surplus bytes on keep-alive paths.
        leftover.clear();

        if (head_end == std::string::npos)
        {
            if (!first_request && buffer.empty())
            {
                // Client closed an idle kept-alive connection. The previous
                // response was fully written, so nothing is lost; close
                // quietly instead of emitting 408 noise.
                return RoundOutcome::close_connection;
            }
            ++ctx.stats.rejected_requests;
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
            return RoundOutcome::close_connection;
        }

        auto const parse = http::parse_request_head(std::string_view{buffer.data(), head_end});
        if (parse.error != http::RequestErrorCode::none)
        {
            ++ctx.stats.rejected_requests;
            auto reason = std::string{"request rejected: "};
            reason.append(http::request_error_name(parse.error));
            log_diagnostic("request.rejected",
                           {
                               {"status", std::to_string(http::request_error_status(parse.error)), false},
                               {"reason", http::request_error_name(parse.error),                   false}
            });
            write_error_response(stream, http::request_error_status(parse.error), reason);
            return RoundOutcome::close_connection;
        }

        // Connection framing decision for this round (RFC 9112 §9.3): the
        // client's Connection header, the keep-alive policy, and the parked-
        // connection cap compose in http::connection_preference_for_response.
        // The parked count read here is a hint for the response header; the
        // authoritative slot acquisition happens when the connection parks,
        // so a keep-alive header is advisory — the server may still close
        // early (cap reached, shutdown), which is legal for a hint.
        auto const keep_alive_policy = keep_alive_policy_for(ctx);
        auto const connection_header = find_header_value(parse.request, "connection");
        auto const decision =
            http::connection_preference_for_response(parse.request.version, connection_header, keep_alive_policy,
                                                     parked_keep_alive_connections.load(std::memory_order_relaxed));

        auto body_tail = std::string{buffer.substr(head_end)};
        auto body = std::string{};
        if (parse.request.has_content_length && parse.request.content_length > 0U)
        {
            auto const expected = static_cast<std::size_t>(parse.request.content_length);
            // Media upload routes permit up to max_upload_size; every other
            // client-server route uses the smaller general body cap.
            auto const effective_cap = [&]() -> std::size_t {
                if (ctx.dispatch_mode == HttpDispatchMode::client_server && parse.request.method == "POST")
                {
                    auto const& t = parse.request.target;
                    auto const is_media =
                        (t == "/_matrix/media/v3/upload" || t.starts_with("/_matrix/media/v3/upload?") ||
                         t == "/_matrix/client/v1/media/upload" || t.starts_with("/_matrix/client/v1/media/upload?"));
                    if (is_media)
                    {
                        auto const parsed =
                            config::parse_size_limit(ctx.runtime.homeserver.config.security().media.max_upload_size);
                        auto const raw = parsed.valid ? parsed.bytes : std::uint64_t{104857600U};
                        return raw > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                             : static_cast<std::size_t>(raw);
                    }
                }
                return body_size_cap(limits);
            }();
            if (expected > effective_cap)
            {
                ++ctx.stats.rejected_requests;
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
                if (ctx.dispatch_mode == HttpDispatchMode::client_server && !ctx.runtime.cors.allowed_origins.empty())
                {
                    auto const origin = find_header_value(parse.request, "origin");
                    if (!origin.empty())
                    {
                        for (auto const& allowed : ctx.runtime.cors.allowed_origins)
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
                return RoundOutcome::close_connection;
            }
            // Drain the body exactly: read precisely Content-Length bytes and
            // keep any surplus (a pipelined next request) for the next round.
            auto body_result = read_remaining_body(stream, std::move(body_tail), expected, effective_cap);
            if (!body_result.complete)
            {
                ++ctx.stats.rejected_requests;
                log_diagnostic("request.rejected",
                               {
                                   {"method",              parse.request.method,                                       false},
                                   {"target",              observability::sanitized_http_target(parse.request.target), false},
                                   {"status",              "408",                                                      false},
                                   {"expected_body_bytes", std::to_string(expected),                                   false},
                                   {"received_body_bytes", std::to_string(body_result.body.size()),                    false},
                                   {"reason",              "request body incomplete or timed out",                     false}
                });
                write_error_response(stream, 408U, "request body incomplete or timed out");
                return RoundOutcome::close_connection;
            }
            body = std::move(body_result.body);
            leftover = std::move(body_result.leftover);
        }
        else
        {
            // No body declared. Chunked transfer coding is rejected by the
            // parser, so a body can only arrive via Content-Length; every
            // byte past the head therefore belongs to the next request.
            leftover = std::move(body_tail);
        }

        auto const local_request = build_local_request(parse.request, std::move(body), ctx.peer_addr);
        log_diagnostic("request.dispatch",
                       {
                           {"method",           local_request.method,                                       false},
                           {"target",           observability::sanitized_http_target(local_request.target), false},
                           {"body_bytes",       std::to_string(local_request.body.size()),                  false},
                           {"has_access_token", local_request.access_token.empty() ? "false" : "true",      false}
        });

        auto result = route_request(ctx.runtime, local_request, ctx.dispatch_mode);

        if (result.status == DispatchResult::Status::needs_wait)
        {
            auto* notifier = ctx.runtime.sync_notifier.get();
            if (notifier == nullptr)
            {
                write_error_response(stream, 503U, matrix_error("M_UNKNOWN", "sync notifier unavailable"));
                return RoundOutcome::close_connection;
            }

            if (ctx.sync_pool != nullptr)
            {
                // Hand off to the dedicated sync pool. The current main-pool thread
                // is freed immediately. The sync pool thread owns the fd exclusively
                // from this point and must close it when done (or hand it back to
                // the owner pool for the next keep-alive round).
                //
                // Poll in 5-second slices so that server shutdown (sync_pool.request_stop())
                // is bounded to at most one slice even when clients request long timeouts.
                // Clients re-poll immediately after an empty 200, so the slicing is transparent.
                auto const fd = stream.fd();
                auto const wait = result.wait;
                // Everything the sync task outlives `ctx` for is copied out here:
                // by the time this lambda runs, serve_request_round (and its
                // caller's ConnectionContext) may already be gone. runtime and
                // stats themselves outlive every pool task (main.cpp stops the
                // pools before the runtime is torn down).
                auto* runtime_ptr = &ctx.runtime;
                auto* stats_ptr = &ctx.stats;
                auto peer_addr_copy = ctx.peer_addr;
                auto const dispatch_mode = ctx.dispatch_mode;
                auto* sync_pool_ptr = ctx.sync_pool;
                auto* owner_pool_ptr = ctx.owner_pool;
                auto const idle_timeout_seconds = keep_alive_policy.idle_timeout_seconds;
                // write_fn routes TLS writes through the OpenSSL layer; for
                // plain HTTP it is null and ::send() is used directly.
                auto write_fn = make_async_write_fn(tls);
                // The submitted sync task must capture by VALUE only; a
                // reference to the enclosing ctx would dangle once this round
                // returns transferred.
                auto submitted = sync_pool_ptr->submit([fd, write_fn = std::move(write_fn), runtime_ptr, stats_ptr,
                                                        request_copy = local_request, wait, notifier, sync_pool_ptr,
                                                        decision, idle_timeout_seconds, peer_addr_copy, dispatch_mode,
                                                        owner_pool_ptr, tls]() mutable {
                    // Re-wait loop: after each notifier fire, call the handler with
                    // can_wait=true.  If the handler returns needs_wait the wakeup was
                    // caused by an event irrelevant to this connection (e.g. another
                    // user's device key upload); advance wait_params past the irrelevant
                    // bump and continue polling.  If it returns complete, send immediately.
                    // `wait` is captured const from the outer scope; use wait_params for
                    // the mutable cursor that tracks the advancing since-values.
                    // Local aliases so the loop body below keeps its original
                    // shape; the pointers were captured because this task can
                    // outlive the ConnectionContext that created it.
                    auto& runtime = *runtime_ptr;
                    auto& stats = *stats_ptr;
                    auto* sync_pool = sync_pool_ptr;
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
                    auto const formatted =
                        format_response(final_result.response.status, final_result.response.body,
                                        final_result.response.headers, decision, idle_timeout_seconds);
                    if (write_fn)
                    {
                        std::ignore = write_fn(formatted);
                    }
                    else
                    {
                        std::ignore = send_all(fd, formatted);
                    }
                    // Keep-alive continuation: when the client asked to keep the
                    // connection open, hand the fd back to the owner pool so the
                    // next request is served on a main-pool worker (pool
                    // separation preserved). All captures are values — this
                    // task may be the last thing referencing the connection.
                    auto const continue_connection = [&]() -> bool {
                        if (decision != http::ConnectionPreference::keep_alive || owner_pool_ptr == nullptr)
                        {
                            return false;
                        }
                        return owner_pool_ptr->submit([fd, tls, peer_addr_copy, dispatch_mode, sync_pool_ptr,
                                                       owner_pool_ptr, runtime_ptr, stats_ptr] {
                            auto guard = core::SocketHandle{fd};
                            auto connection_ctx =
                                ConnectionContext{*runtime_ptr,  *stats_ptr,     dispatch_mode,
                                                  sync_pool_ptr, owner_pool_ptr, std::move(peer_addr_copy)};
                            if (serve_connection(fd, tls, connection_ctx) == ServeOutcome::transferred)
                            {
                                // The next long-poll (or its continuation) owns
                                // the fd now.
                                std::ignore = guard.release();
                            }
                            else
                            {
                                std::ignore = ::shutdown(fd, SHUT_RDWR);
                                // ~guard closes the fd on any exit path.
                            }
                        });
                    };
                    if (!continue_connection())
                    {
                        std::ignore = ::shutdown(fd, SHUT_RDWR);
                        ::close(fd);
                    }
                });
                if (submitted)
                {
                    return RoundOutcome::transferred; // fd is now owned by the sync pool thread
                }
                // Sync pool is stopping; fall through to synchronous wait.
                // write_fn was moved-from into the rejected lambda; the sync
                // fallback path below uses stream.write() directly so that is fine.
            }

            // No sync_pool supplied (tests, pool shutting down): block this thread
            // until new events arrive or the timeout expires.
            // TLS connections use serve_tls_http which passes a sync_pool; they
            // only reach this path if the pool is stopping.
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
                            auto interim = handle_client_server_request(ctx.runtime, local_request, true);
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
                    log_swallowed_exception("serve_request_round_sync_wait");
                }
                if (!dispatched)
                {
                    result = handle_client_server_request(ctx.runtime, local_request, false);
                }
            }
        }

        ++ctx.stats.completed_requests;
        log_diagnostic("request.completed",
                       {
                           {"method",         local_request.method,                                       false},
                           {"target",         observability::sanitized_http_target(local_request.target), false},
                           {"status",         std::to_string(result.response.status),                     false},
                           {"response_bytes", std::to_string(result.response.body.size()),                false}
        });
        auto const formatted = format_response(result.response.status, result.response.body, result.response.headers,
                                               decision, keep_alive_policy.idle_timeout_seconds);
        if (!send_all(stream, formatted))
        {
            return RoundOutcome::close_connection;
        }
        return decision == http::ConnectionPreference::keep_alive ? RoundOutcome::continue_keep_alive
                                                                  : RoundOutcome::close_connection;
    }

    // Serves a whole connection: request rounds in a sequential loop, parking
    // between rounds for up to the keep-alive idle window. The first request
    // is served immediately (no parking — the client just sent bytes, so no
    // worker is held without work); each subsequent round first acquires one
    // process-wide parked-connection slot. When the operator's cap is reached
    // the connection closes after its current response instead of parking, so
    // a single client cannot park a worker thread per connection beyond the
    // configured budget. Idle parking is bounded ONLY by the idle window (the
    // slowloris policy is not applied to a quiet connection — see
    // http::connection_should_close); once request bytes arrive, the full
    // per-request slowloris machinery applies to that head/body read again.
    [[nodiscard]] auto serve_connection(
        int fd,
        std::shared_ptr<TlsConnection> tls, // SHARED_PTR: reviewed — read/write pool split
        ConnectionContext& ctx) -> ServeOutcome
    {
        auto stream = make_connection_stream(fd, tls);
        auto leftover = std::string{};
        auto first_request = true;
        while (true)
        {
            auto const policy = keep_alive_policy_for(ctx);
            // Only park when there is nothing buffered: a pipelined next
            // request already sitting in `leftover` is served immediately —
            // polling the socket would miss it (the bytes are in our buffer,
            // not the kernel's) and the connection would wrongly idle out.
            if (!first_request && leftover.empty())
            {
                auto slot = ParkedKeepAliveSlot::try_acquire(policy);
                if (!slot.has_value())
                {
                    log_diagnostic("connection.keep_alive_cap_reached",
                                   {
                                       {"limit", std::to_string(policy.max_connections), false}
                    });
                    return ServeOutcome::connection_closed;
                }
                auto const wait = wait_for_next_request(*stream, ctx.owner_pool, policy);
                // ~slot releases the parked-connection slot the moment the
                // wait ends — bytes arrived, the idle window expired, or the
                // peer went away. The cap bounds parked connections, not
                // active requests.
                if (wait != NextRequestWait::data_ready)
                {
                    if (wait == NextRequestWait::idle_expired)
                    {
                        log_diagnostic("connection.keep_alive_idle_expired",
                                       {
                                           {"idle_seconds", std::to_string(policy.idle_timeout_seconds), false}
                        });
                    }
                    return ServeOutcome::connection_closed;
                }
            }
            auto const was_first_request = first_request;
            first_request = false;
            switch (serve_request_round(*stream, tls, ctx, leftover, was_first_request))
            {
            case RoundOutcome::close_connection:
                return ServeOutcome::connection_closed;
            case RoundOutcome::continue_keep_alive:
                continue;
            case RoundOutcome::transferred:
                // The sync-pool task (or the continuation it submits) owns the
                // fd from here; the caller must NOT close it.
                return ServeOutcome::transferred;
            }
        }
    }

} // namespace

auto dispatch_local_http_request(ClientServerRuntime& runtime, LocalHttpRequest const& request, HttpDispatchMode mode)
    -> LocalHttpResponse
{
    // This public API preserves its original blocking behaviour for backward
    // compatibility (tests, one-off callers). The server's hot path uses
    // route_request() + serve_connection() with a dedicated sync_pool instead.
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
    // Direct callers (tests, one-off embeds) keep the historical one-request-
    // per-call contract: with no owning pool the keep-alive policy disables
    // parking (see keep_alive_policy_for), so this serves a single round and
    // reports whether the fd was transferred to the sync pool.
    auto connection_ctx = ConnectionContext{runtime, stats, dispatch_mode, sync_pool, nullptr, std::string{peer_addr}};
    return serve_connection(client_fd, nullptr, connection_ctx) == ServeOutcome::transferred;
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
        // SOCK_CLOEXEC: accepted client sockets must not leak into worker
        // subprocesses spawned via posix_spawn/fork() (federation workers,
        // thumbnail worker) while a connection is still open. Matches the
        // SOCK_CLOEXEC listening-socket pattern in net/tcp_acceptor.cpp.
        auto raw_client = ::accept4(acceptor.fd(), reinterpret_cast<sockaddr*>(&peer_sa), &peer_len, SOCK_CLOEXEC);
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
        auto submitted = pool.submit(
            [&runtime, &stats, dispatch_mode, sync_pool, owner_pool = &pool, fd, peer_addr = std::move(peer_addr)] {
                auto guard = core::SocketHandle{fd};
                ++stats.accepted_connections;
                auto connection_ctx =
                    ConnectionContext{runtime, stats, dispatch_mode, sync_pool, owner_pool, std::move(peer_addr)};
                auto const handed_off = serve_connection(fd, nullptr, connection_ctx) == ServeOutcome::transferred;
                if (handed_off)
                {
                    // The sync pool thread (or the keep-alive continuation it
                    // submits back to this pool) owns the fd; do NOT shut it
                    // down here.
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
        // SOCK_CLOEXEC: see the plain-HTTP accept loop above for why this
        // matters — TLS long-poll connections are held open for the longest,
        // maximizing the window during which a leaked fd could be inherited.
        auto raw_client =
            ::accept4(acceptor.fd(), reinterpret_cast<sockaddr*>(&tls_peer_sa), &tls_peer_len, SOCK_CLOEXEC);
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
        auto submitted = pool.submit([&tls_context, &runtime, &stats, dispatch_mode, sync_pool, owner_pool = &pool, fd,
                                      tls_peer_addr = std::move(tls_peer_addr)] {
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
            // _Sp_counted_ptr_inplace co-allocation is inlined. The connection
            // stream (read phase, this thread), the sync-pool write lambda, and
            // the keep-alive continuation that re-enters serve_connection each
            // hold a copy; the last one to finish cleans up.
            auto tls_unique = std::make_unique<TlsConnection>(std::move(*accepted_tls.connection));
            auto tls_shared = std::shared_ptr<TlsConnection>{// SHARED_PTR: reviewed — cross-thread TLS ownership
                                                             std::move(tls_unique)};

            auto connection_ctx =
                ConnectionContext{runtime, stats, dispatch_mode, sync_pool, owner_pool, std::move(tls_peer_addr)};
            auto const transferred = serve_connection(fd, tls_shared, connection_ctx) == ServeOutcome::transferred;
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
