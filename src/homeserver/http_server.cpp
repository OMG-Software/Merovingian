// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/http_server.hpp"

#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/client_address.hpp"
#include "merovingian/http/connection_guard.hpp"
#include "merovingian/http/connection_limiter.hpp"
#include "merovingian/http/keep_alive.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/http/request_limits.hpp"
#include "merovingian/net/connection_parker.hpp"
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
#include <fcntl.h>
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

    // Waits for one readiness event on `fd`, bounded by `timeout_ms`. Returns
    // false on timeout or error so the caller fails the I/O rather than
    // retrying forever.
    [[nodiscard]] auto poll_for_plain_io(int fd, short events, int timeout_ms) noexcept -> bool
    {
        auto entry = pollfd{};
        entry.fd = fd;
        entry.events = events;
        auto const poll_result = ::poll(&entry, 1U, timeout_ms);
        return poll_result > 0 && (entry.revents & events) != 0;
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

    // Per-read I/O timeout. Every wait below is also bounded by the deadline
    // of whichever phase the connection is in; this is the ceiling.
    constexpr auto receive_timeout_milliseconds = 15000;
    // B3: slowloris hardening for the request HEAD, which a worker reads once
    // the connection is readable (ADR-0077: the first byte is waited for by
    // the dispatcher, never by a worker):
    //   - overall request-head deadline (30 s): a slow client can dribble a
    //     head indefinitely without ever filling the head buffer.
    //   - per-byte inter-byte cap (5 s) between bytes of the head.
    // A client that dribbles heads holds at most its own share of the workers
    // (max(1, pool / 4)) for at most 30 s each.
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
        // Input already held above the socket, which poll() cannot see.
        [[nodiscard]] virtual auto has_buffered_input() const noexcept -> bool
        {
            return false;
        }
        [[nodiscard]] virtual auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t = 0;
        [[nodiscard]] virtual auto write(std::string_view data) noexcept -> std::ptrdiff_t = 0;
    };

    // A plain-HTTP connection. The descriptor is non-blocking for the life of
    // the connection (see make_connection_stream), so both directions retry
    // against a deadline here rather than parking a worker in the kernel.
    //
    // ADR-0054 made TLS sockets non-blocking for life and stated the rule this
    // class now also obeys: no code below the HTTP layer may perform a blocking
    // I/O call on a connection descriptor, because every timeout above is
    // expressed as poll() on that descriptor and that is only a timeout if the
    // call beneath it cannot block. Reads here were already guarded by the HTTP
    // layer's poll(POLLIN); writes were not, so a peer that accepted a
    // connection and then stopped reading held a worker inside ::send() for as
    // long as it liked.
    class PlainConnectionStream final : public ConnectionStream
    {
    public:
        PlainConnectionStream(int file_descriptor, int io_timeout_milliseconds) noexcept
            : m_fd{file_descriptor}
            , m_io_timeout_ms{io_timeout_milliseconds}
        {
        }

        [[nodiscard]] auto fd() const noexcept -> int override
        {
            return m_fd;
        }

        [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t override
        {
            while (true)
            {
                auto const received = ::recv(m_fd, buffer, capacity, 0);
                if (received >= 0)
                {
                    return received;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                // Callers poll POLLIN before reading, so EAGAIN here is a
                // spurious readiness (a discarded packet, a checksum failure).
                // Wait for real data rather than reporting a dead connection.
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    return -1;
                }
                if (!poll_for_plain_io(m_fd, POLLIN, m_io_timeout_ms))
                {
                    return -1;
                }
            }
        }

        [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t override
        {
            while (true)
            {
                // MSG_NOSIGNAL avoids SIGPIPE on early client close (POSIX 2008).
                auto const sent = ::send(m_fd, data.data(), data.size(), MSG_NOSIGNAL);
                if (sent >= 0)
                {
                    return sent;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    return -1;
                }
                // The peer's receive window is full. Wait for it to drain, but
                // only for as long as the deadline allows: a client that never
                // reads must cost one bounded timeout, not a parked worker.
                if (!poll_for_plain_io(m_fd, POLLOUT, m_io_timeout_ms))
                {
                    return -1;
                }
            }
        }

    private:
        int m_fd;
        int m_io_timeout_ms;
    };

    // A TLS connection, borrowed from the HttpConnection that owns it for the
    // length of one request round (or one sync-pool response).
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

        [[nodiscard]] auto has_buffered_input() const noexcept -> bool override
        {
            return m_connection.has_pending_input();
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

    // ---------------------------------------------------------------------
    // Connections and the dispatcher (ADR-0077)
    //
    // Matrix v1.19 is served over HTTP/1.1, where persistent connections are
    // the default (RFC 9112 §9.3). A connection is served one request round at
    // a time: read one request, drain its body exactly, write one response.
    // Between rounds, and before the first one, the connection is held by the
    // dispatcher (net::ConnectionParker), NOT by a worker thread; a worker gets
    // it back only once it is readable. Pipelining (more than one outstanding
    // request) is NOT supported: pipelined bytes are buffered and served in
    // order, one response at a time.
    //
    // Ownership: every connection is an HttpConnection behind a
    // std::unique_ptr, owned by exactly one of the parker, one pool task, or
    // one sync-pool task at any moment. Destroying it closes the socket and
    // releases everything it holds (per-IP slot, parking reservation).
    // ---------------------------------------------------------------------

    using ConnectionOwner = std::unique_ptr<net::ConnectionParker::Connection>;

    // A counted slot in one of the dispatcher's parking budgets (kept-alive
    // connections between requests; new connections before their first
    // request). The counter is shared so a reservation may outlive the
    // dispatcher that issued it.
    class ParkingReservation final
    {
    public:
        using Counter = std::shared_ptr<std::atomic<std::uint32_t>>; // SHARED_PTR: reviewed — outlives the dispatcher

        ParkingReservation(ParkingReservation const&) = delete;
        auto operator=(ParkingReservation const&) -> ParkingReservation& = delete;
        ParkingReservation(ParkingReservation&& other) noexcept
            : m_counter{std::move(other.m_counter)}
        {
        }
        auto operator=(ParkingReservation&& other) noexcept -> ParkingReservation&
        {
            if (this != &other)
            {
                release();
                m_counter = std::move(other.m_counter);
            }
            return *this;
        }
        ~ParkingReservation()
        {
            release();
        }

        // A slot when fewer than `cap` are held; nullopt at the cap. A cap of
        // 0 means unbounded.
        [[nodiscard]] static auto try_acquire(Counter const& counter, std::uint32_t cap)
            -> std::optional<ParkingReservation>
        {
            auto current = counter->load(std::memory_order_relaxed);
            while (cap == 0U || current < cap)
            {
                if (counter->compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                                   std::memory_order_relaxed))
                {
                    return ParkingReservation{counter};
                }
            }
            return std::nullopt;
        }

    private:
        explicit ParkingReservation(Counter counter) noexcept
            : m_counter{std::move(counter)}
        {
        }
        auto release() noexcept -> void
        {
            if (m_counter != nullptr)
            {
                m_counter->fetch_sub(1U, std::memory_order_relaxed);
                m_counter = nullptr;
            }
        }

        Counter m_counter{};
    };

    // One client connection and everything that travels with it.
    class HttpConnection final : public net::ConnectionParker::Connection
    {
    public:
        HttpConnection(core::SocketHandle client_socket, HttpDispatchMode dispatch_mode, std::string peer,
                       std::string key) noexcept
            : socket{std::move(client_socket)}
            , mode{dispatch_mode}
            , peer_addr{std::move(peer)}
            , client_key{std::move(key)}
            , opened_at{std::chrono::steady_clock::now()}
        {
        }
        HttpConnection(HttpConnection const&) = delete;
        auto operator=(HttpConnection const&) -> HttpConnection& = delete;
        HttpConnection(HttpConnection&&) = delete;
        auto operator=(HttpConnection&&) -> HttpConnection& = delete;
        ~HttpConnection() override
        {
            // TLS state first (it does not own the descriptor), then an
            // orderly shutdown; ~socket closes the descriptor last.
            tls.reset();
            if (socket.valid())
            {
                std::ignore = ::shutdown(socket.native_handle(), SHUT_RDWR);
            }
        }

        [[nodiscard]] auto fd() const noexcept -> int override
        {
            return socket.native_handle();
        }

        // Pipelined bytes already read past the previous request, or TLS input
        // OpenSSL holds: the next request is here even if the socket is quiet.
        [[nodiscard]] auto has_buffered_input() const noexcept -> bool override
        {
            return !leftover.empty() || (tls.has_value() && tls->has_pending_input());
        }

        auto on_park_expired() noexcept -> void override
        {
            try
            {
                if (first_request)
                {
                    log_diagnostic("connection.first_byte_timeout",
                                   {
                                       {"phase", tls_handshake_owed ? "tls_handshake" : "request", false}
                    });
                }
                else
                {
                    log_diagnostic("connection.keep_alive_idle_expired", {});
                }
            }
            catch (...)
            {
            }
        }

        // Declared first so it is destroyed last: everything below may still
        // refer to the descriptor while it is torn down.
        core::SocketHandle socket;
        // ADR-0072: the connection's per-IP slot; empty when exempt.
        std::optional<http::ConnectionLimiter::Slot> connection_slot{};
        std::optional<TlsConnection> tls{};
        // Set on a TLS listener until the handshake has run (on a worker).
        std::optional<std::reference_wrapper<TlsServerContext>> tls_handshake_owed{};
        HttpDispatchMode mode;
        std::string peer_addr;
        // The per-client worker-share key; empty for a trusted proxy.
        std::string client_key;
        // Bytes read past the previous request (a pipelined next request).
        std::string leftover{};
        std::uint32_t requests_served{0U};
        std::chrono::steady_clock::time_point opened_at;
        bool first_request{true};
        // Held while the connection is parked (see ParkingReservation).
        std::optional<ParkingReservation> parked_reservation{};
    };

    [[nodiscard]] auto http_connection(ConnectionOwner const& owner) -> HttpConnection&
    {
        // Only HttpConnections are ever parked on an HTTP dispatcher.
        return dynamic_cast<HttpConnection&>(*owner);
    }

    // Everything a request round needs besides the connection itself.
    // `runtime` and `stats` outlive every pool task (main.cpp stops the pools
    // before the runtime is torn down). `dispatcher` is null for direct
    // serve_one_http_connection calls, which never keep a connection alive.
    struct ConnectionContext final
    {
        ClientServerRuntime& runtime;
        HttpServeStats& stats;
        net::ThreadPool* sync_pool;                     // may be null (tests, no long-poll offload)
        std::shared_ptr<HttpConnectionDispatcher::Impl> // SHARED_PTR: reviewed — pool tasks keep the dispatcher alive
            dispatcher;
        HttpServeTuning tuning;
        HttpDispatchMode dispatch_mode;
        std::string peer_addr;
    };

    struct ConnectionAdmission final
    {
        bool admitted{false};
        std::optional<http::ConnectionLimiter::Slot> slot{};
        // The per-client worker-share key (ADR-0077); empty when exempt.
        std::string client_key{};
    };

    // ADR-0072: decided at accept time, before a byte is read. A connection
    // from an address in server.trusted_proxies is exempt, because a reverse
    // proxy carries many clients over its own address; per-client limiting
    // then relies on the proxy and on the per-IP rate limiter, which sees the
    // forwarded address. Everything else is counted under its
    // client_address_key and refused once that key holds
    // server.http.max_connections_per_ip connections. The same key (and the
    // same exemption) is the connection's per-client worker share (ADR-0077).
    [[nodiscard]] auto admit_connection(ClientServerRuntime& runtime, std::string const& peer_addr)
        -> ConnectionAdmission
    {
        auto const& server = runtime.homeserver.config.server();
        if (std::ranges::find(server.trusted_proxies, peer_addr) != server.trusted_proxies.end())
        {
            return {true, std::nullopt, {}};
        }
        if (!runtime.connection_limiter)
        {
            return {false, std::nullopt, {}};
        }
        auto key = http::client_address_key(peer_addr, server.http.ipv6_client_prefix_length);
        if (key.empty())
        {
            // Fail closed: an address we could not render still shares one
            // budget rather than escaping the per-client caps.
            key = "unknown";
        }
        auto slot = runtime.connection_limiter->try_acquire(key, server.http.max_connections_per_ip);
        if (!slot.has_value())
        {
            return {false, std::nullopt, {}};
        }
        auto admission = ConnectionAdmission{};
        admission.admitted = true;
        admission.slot.emplace(std::move(*slot));
        admission.client_key = std::move(key);
        return admission;
    }

    enum class RoundOutcome : std::uint8_t
    {
        // One request round finished and the connection must close.
        close_connection,
        // One request round finished with Connection: keep-alive; the
        // connection goes back to the dispatcher for its next request.
        continue_keep_alive,
        // The request was a long-poll handed off to the sync pool, which now
        // owns the connection (and hands it back to the dispatcher itself).
        transferred,
    };

    // The effective keep-alive policy for one connection. Keep-alive is off
    // when there is no dispatcher to park the connection on: direct
    // serve_one_http_connection callers keep the one-request-per-call
    // contract.
    [[nodiscard]] auto keep_alive_policy_for(ConnectionContext const& ctx) noexcept -> http::KeepAlivePolicy
    {
        auto const& http_config = ctx.runtime.homeserver.config.server().http;
        auto const enabled = http_config.keep_alive && ctx.dispatcher != nullptr;
        return {enabled, http_config.keep_alive_idle_seconds, http_config.keep_alive_max_connections};
    }

    [[nodiscard]] auto set_socket_nonblocking(int fd) noexcept -> bool
    {
        auto const flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0)
        {
            return false;
        }
        return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    // Returns nullptr when the plain socket cannot be put into non-blocking
    // mode; the caller closes the connection. Failing closed matters: a socket
    // left blocking silently reinstates the unbounded ::send() this was written
    // to remove, and nothing above would notice.
    [[nodiscard]] auto make_connection_stream(HttpConnection& connection) -> std::unique_ptr<ConnectionStream>
    {
        if (connection.tls.has_value())
        {
            // accept_tls_connection already left this descriptor non-blocking
            // and deliberately never restores it (ADR-0054).
            return std::make_unique<TlsConnectionStream>(*connection.tls);
        }
        auto const fd = connection.fd();
        if (!set_socket_nonblocking(fd))
        {
            log_diagnostic("connection.nonblocking_failed",
                           {
                               {"fd",    std::to_string(fd),    false},
                               {"errno", std::to_string(errno), false}
            });
            return nullptr;
        }
        return std::make_unique<PlainConnectionStream>(fd, receive_timeout_milliseconds);
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

    // Returned by recv_with_timeout when the poll budget expired with no data,
    // as distinct from -1 for a peer close or socket error. The caller loops on
    // it so the slowloris caps below are re-evaluated and the specific one that
    // expired is the thing that ends the request (and gets logged).
    constexpr auto recv_budget_expired = std::ptrdiff_t{-2};

    // `budget_ms` bounds this single poll. It must be the SMALLEST of the
    // per-read timeout and the time left on any slowloris cap the caller is
    // enforcing: the caps are only checked between reads, so a poll allowed to
    // outlast one makes that cap unenforceable. That was a real defect — with a
    // fixed 15s poll and a 5s inter-byte cap, a peer that stopped mid-body held
    // the worker for the full 15s and the inter-byte cap never once fired.
    [[nodiscard]] auto recv_with_timeout(ConnectionStream& stream, char* buffer, std::size_t capacity,
                                         int budget_ms) noexcept -> std::ptrdiff_t
    {
        // Input OpenSSL already holds is invisible to poll(): read it now, or
        // the wait below runs out on bytes that have already arrived.
        if (stream.has_buffered_input())
        {
            return stream.read(buffer, capacity);
        }
        auto entry = pollfd{};
        entry.fd = stream.fd();
        entry.events = POLLIN;
        auto const poll_result = ::poll(&entry, 1U, budget_ms);
        if (poll_result == 0)
        {
            return recv_budget_expired;
        }
        if (poll_result < 0)
        {
            return -1;
        }
        if ((entry.revents & POLLIN) == 0)
        {
            return -1;
        }
        return stream.read(buffer, capacity);
    }

    // The poll budget for one read: whichever of the per-read timeout, the
    // overall deadline, and the inter-byte cap runs out first. Never negative —
    // an already-expired cap yields a zero-length poll and the caller's loop-top
    // check then ends the request.
    [[nodiscard]] auto recv_budget_ms(std::chrono::steady_clock::time_point now,
                                      std::chrono::steady_clock::time_point deadline,
                                      std::chrono::steady_clock::time_point last_byte) noexcept -> int
    {
        auto const to_deadline = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        auto const to_inter_byte =
            std::chrono::duration_cast<std::chrono::milliseconds>((last_byte + inter_byte_timeout) - now).count();
        auto const smallest =
            std::min({static_cast<std::int64_t>(receive_timeout_milliseconds), static_cast<std::int64_t>(to_deadline),
                      static_cast<std::int64_t>(to_inter_byte)});
        return smallest <= 0 ? 0 : static_cast<int>(smallest);
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
            if (now - start >= request_head_deadline)
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
            if (now - last_byte >= inter_byte_timeout)
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
            // Bound the poll by whichever cap expires first, so neither the
            // overall deadline nor the inter-byte cap can be outlived by a
            // single read. On expiry, loop so the check above names the cap.
            auto const received = recv_with_timeout(stream, chunk.data(), wanted,
                                                    recv_budget_ms(now, start + request_head_deadline, last_byte));
            if (received == recv_budget_expired)
            {
                continue;
            }
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

    // Reads exactly `expected` body bytes (never more than `cap`) under the
    // minimum body rate (HTTP-1, ADR-0077): once `grace` has passed since the
    // body read started, the bytes received so far must be at least
    // `min_bytes_per_second` x (elapsed - grace). The rule is continuous: the
    // moment the count falls behind the line the read ends and the caller
    // answers 408. It replaced a whole-body deadline (30 s + length / 16 KiB)
    // with a 5 s inter-byte gap, which let a client that sent one byte every
    // 4.9 s hold a worker for most of an hour on a large upload.
    //
    // Bytes that arrived with the head count as received. A legitimate client
    // at or above the floor never trips the rule however large the body;
    // with the production values (10 s, 16 KiB/s) a 1 MiB body may take up to
    // 74 s.
    [[nodiscard]] auto read_remaining_body(ConnectionStream& stream, std::string head_tail, std::size_t expected,
                                           std::size_t cap, HttpServeTuning const& tuning) -> BodyReadResult
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
        auto const rate = std::max<std::uint64_t>(1U, tuning.body_min_bytes_per_second);
        auto const start = std::chrono::steady_clock::now();
        while (body.size() < expected)
        {
            auto const now = std::chrono::steady_clock::now();
            // The instant the bytes held so far stop satisfying the rule:
            // grace plus the time the floor rate needs to deliver them.
            auto const earned = std::chrono::milliseconds{
                static_cast<std::int64_t>((static_cast<std::uint64_t>(body.size()) * 1000U) / rate)};
            auto const trips_at = start + tuning.body_rate_grace + earned;
            if (now >= trips_at)
            {
                log_diagnostic(
                    "request.body_slowloris",
                    {
                        {"reason",         "minimum_body_rate",                                                      false},
                        {"elapsed_ms",
                         std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count()),
                         false                                                                                            },
                        {"bytes_received", std::to_string(body.size()),                                              false},
                        {"bytes_expected", std::to_string(expected),                                                 false}
                });
                return {};
            }
            auto const remaining = expected - body.size();
            auto const wanted = remaining < chunk.size() ? remaining : chunk.size();
            // Never wait past the moment the rule would trip: the rule is only
            // checked between reads, so a longer poll would make it
            // unenforceable.
            auto const to_trip = std::chrono::duration_cast<std::chrono::milliseconds>(trips_at - now).count();
            auto const budget = std::max<std::int64_t>(
                1, std::min<std::int64_t>(static_cast<std::int64_t>(receive_timeout_milliseconds), to_trip));
            auto const received = recv_with_timeout(stream, chunk.data(), wanted, static_cast<int>(budget));
            if (received == recv_budget_expired)
            {
                continue;
            }
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

    // Reads the `Origin` header straight out of the raw head bytes. The
    // transport-layer error paths need it before (or instead of) a successful
    // parse — a head that was too large, timed out, or failed to parse still
    // has to answer a browser with CORS headers, and by then there is no
    // http::RequestHead to consult.
    [[nodiscard]] auto origin_from_raw_head(std::string_view raw) -> std::string
    {
        auto constexpr name = std::string_view{"origin"};
        auto rest = raw;
        // Skip the request line; header fields start after the first CRLF.
        auto const first_break = rest.find("\r\n");
        if (first_break == std::string_view::npos)
        {
            return {};
        }
        rest.remove_prefix(first_break + 2U);
        while (!rest.empty())
        {
            auto const line_end = rest.find("\r\n");
            auto const line = rest.substr(0U, line_end == std::string_view::npos ? rest.size() : line_end);
            if (line.empty())
            {
                return {};
            }
            auto const colon = line.find(':');
            if (colon != std::string_view::npos && colon == name.size())
            {
                auto matches = true;
                for (auto index = std::size_t{0U}; index < name.size(); ++index)
                {
                    auto const c = line[index];
                    auto const lower = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
                    if (lower != name[index])
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                {
                    auto value = line.substr(colon + 1U);
                    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                    {
                        value.remove_prefix(1U);
                    }
                    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                    {
                        value.remove_suffix(1U);
                    }
                    return std::string{value};
                }
            }
            if (line_end == std::string_view::npos)
            {
                return {};
            }
            rest.remove_prefix(line_end + 2U);
        }
        return {};
    }

    // Spec v1.19 §10.5: the client-server API MUST "supply Cross-Origin
    // Resource Sharing (CORS) headers on all requests". "All" includes the
    // errors this transport layer answers before routing — a 400, 408 or 413
    // without Access-Control-Allow-Origin reaches the browser as a CORS
    // failure, hiding the real status from the client entirely.
    //
    // Access-Control-Allow-Credentials is deliberately never emitted here:
    // these responses are not preflights, and pairing it with a wildcard origin
    // is a CORS-spec violation (see resolve_allow_origin in client_server.cpp).
    [[nodiscard]] auto transport_cors_headers(ConnectionContext const& ctx, std::string_view origin)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto headers = std::vector<std::pair<std::string, std::string>>{};
        if (ctx.dispatch_mode != HttpDispatchMode::client_server || ctx.runtime.cors.allowed_origins.empty() ||
            origin.empty())
        {
            return headers;
        }
        for (auto const& allowed : ctx.runtime.cors.allowed_origins)
        {
            if (allowed == "*" || allowed == origin)
            {
                headers.emplace_back("Access-Control-Allow-Origin",
                                     allowed == "*" ? std::string{"*"} : std::string{origin});
                // Vary: Origin so an intermediate cache cannot serve one
                // origin's response to another.
                headers.emplace_back("Vary", "Origin");
                break;
            }
        }
        return headers;
    }

    auto write_error_response(ConnectionStream& stream, std::uint16_t status, std::string_view body,
                              std::vector<std::pair<std::string, std::string>> const& cors_headers) noexcept -> void
    {
        auto const response = format_response(status, body, cors_headers);
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

} // namespace

auto sync_admission_caps(config::HttpTransportConfig const& settings, std::size_t pool_worker_count) noexcept
    -> SyncAdmissionCaps
{
    auto const configured_pool_size =
        pool_worker_count == 0U ? static_cast<std::size_t>(settings.sync_threads) : pool_worker_count;
    auto const pool_cap = static_cast<std::uint32_t>(std::min<std::size_t>(
        configured_pool_size, static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())));
    auto const global = std::min(settings.sync_max_in_flight, pool_cap);
    return SyncAdmissionCaps{
        .global = global,
        .per_user = std::min(settings.sync_max_per_user, global),
        .per_device = std::min(settings.sync_max_per_device, global),
    };
}

auto http_request_limits_for(ClientServerRuntime const& runtime, HttpDispatchMode dispatch_mode,
                             std::string_view method, std::string_view target) -> http::RequestLimits
{
    auto limits = http::RequestLimits{};
    auto const& runtime_config = runtime.homeserver.config;
    auto const& http_config = runtime_config.server().http;
    auto const body_limit = config::parse_size_limit(http_config.max_body_size);
    if (!body_limit.valid)
    {
        return limits;
    }

    limits.max_start_line_bytes = http_config.max_start_line_bytes;
    limits.max_header_bytes = http_config.max_header_bytes;
    limits.max_header_count = http_config.max_header_count;
    limits.max_body_bytes = body_limit.bytes;
    if (!http::request_limits_are_valid(limits))
    {
        return http::RequestLimits{};
    }

    constexpr auto send_prefix = std::string_view{"/_matrix/federation/v1/send/"};
    if (dispatch_mode == HttpDispatchMode::federation && method == "PUT" && target.starts_with(send_prefix))
    {
        auto const transaction_limit =
            config::parse_size_limit(runtime_config.security().federation.max_transaction_size);
        if (transaction_limit.valid && transaction_limit.bytes <= 64U * 1024U * 1024U)
        {
            limits.max_body_bytes = transaction_limit.bytes;
        }
    }

    return limits;
}

// The dispatcher's internals (ADR-0077). Shared: every pool task that carries a
// connection holds a reference, so a worker finishing a round can always hand
// its connection back (or close it once stopped) even if the public
// HttpConnectionDispatcher has been destroyed.
//
// Threads: the parker thread calls dispatch(); pool workers call serve(); the
// accept threads call accept(); workers and sync-pool tasks call
// park_for_next_request(). None of these holds a lock across another: the
// parker's lock is internal to net::ConnectionParker and is never held while
// this class runs, and the parking counters are atomics.
class HttpConnectionDispatcher::Impl final : public std::enable_shared_from_this<HttpConnectionDispatcher::Impl>
{
public:
    Impl(ClientServerRuntime& runtime_ref, HttpServeStats& stats_ref, net::ThreadPool& pool_ref,
         net::ThreadPool* sync_pool_ptr, HttpServeTuning tuning_value)
        : runtime{runtime_ref}
        , stats{stats_ref}
        , pool{pool_ref}
        , sync_pool{sync_pool_ptr}
        , tuning{tuning_value}
    {
    }
    Impl(Impl const&) = delete;
    auto operator=(Impl const&) -> Impl& = delete;
    Impl(Impl&&) = delete;
    auto operator=(Impl&&) -> Impl& = delete;
    ~Impl() = default;

    [[nodiscard]] auto start() -> bool;
    auto request_stop() -> void;
    [[nodiscard]] auto running() const -> bool;

    // Accept path: an admitted connection waits, parked, for its first byte.
    auto accept(core::SocketHandle socket, std::string peer_addr, HttpDispatchMode mode, ConnectionAdmission admission,
                std::optional<std::reference_wrapper<TlsServerContext>> tls_context) -> void;
    // A worker or a sync-pool task hands a kept-alive connection back.
    auto park_for_next_request(ConnectionOwner owner) -> void;

    [[nodiscard]] auto try_reserve_keep_alive(std::uint32_t cap) -> std::optional<ParkingReservation>
    {
        return ParkingReservation::try_acquire(m_parked_keep_alive, cap);
    }
    [[nodiscard]] auto parked_keep_alive() const noexcept -> std::uint32_t
    {
        return m_parked_keep_alive->load(std::memory_order_relaxed);
    }

    ClientServerRuntime& runtime;
    HttpServeStats& stats;
    net::ThreadPool& pool;
    net::ThreadPool* sync_pool;
    HttpServeTuning const tuning;

private:
    auto park_awaiting_first_request(ConnectionOwner owner) -> void;
    auto dispatch(net::ConnectionParker::Dispatched dispatched) -> void;
    auto serve(net::ConnectionParker::Dispatched dispatched) -> void;

    ParkingReservation::Counter m_parked_keep_alive{std::make_shared<std::atomic<std::uint32_t>>(0U)};
    ParkingReservation::Counter m_parked_new{std::make_shared<std::atomic<std::uint32_t>>(0U)};
    // Created by start() before any listener runs; the pointer never changes
    // afterwards, so the threads that use it need no lock to read it.
    std::unique_ptr<net::ConnectionParker> m_parker{};
};

namespace
{

    [[nodiscard]] auto is_media_upload_target(std::string_view target) noexcept -> bool
    {
        return target == "/_matrix/media/v3/upload" || target.starts_with("/_matrix/media/v3/upload?") ||
               target == "/_matrix/client/v1/media/upload" || target.starts_with("/_matrix/client/v1/media/upload?");
    }

    [[nodiscard]] auto max_upload_bytes(ClientServerRuntime const& runtime) -> std::size_t
    {
        auto const parsed = config::parse_size_limit(runtime.homeserver.config.security().media.max_upload_size);
        auto const raw = parsed.valid ? parsed.bytes : std::uint64_t{104857600U};
        return raw > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                             : static_cast<std::size_t>(raw);
    }

    // Connection framing for one response (RFC 9112 §9.3), decided when the
    // response is about to be written: the client's Connection header and
    // the keep-alive policy, then the per-connection caps (HTTP-8), then a
    // slot in the parked-connection budget. A kept-alive response holds that
    // slot (in the connection) until the connection is next dispatched, so
    // the Keep-Alive header is never a promise the dispatcher cannot keep.
    [[nodiscard]] auto decide_connection(ConnectionContext const& ctx, HttpConnection& connection,
                                         http::HttpVersion version, std::string_view connection_header)
        -> http::ConnectionPreference
    {
        ++connection.requests_served;
        auto const policy = keep_alive_policy_for(ctx);
        auto const parked = ctx.dispatcher != nullptr ? ctx.dispatcher->parked_keep_alive() : 0U;
        auto const preference = http::connection_preference_for_response(version, connection_header, policy, parked);
        if (preference != http::ConnectionPreference::keep_alive || ctx.dispatcher == nullptr)
        {
            return http::ConnectionPreference::close;
        }
        if (connection.requests_served >= ctx.tuning.max_requests_per_connection)
        {
            log_diagnostic("connection.request_cap_reached",
                           {
                               {"requests", std::to_string(connection.requests_served), false}
            });
            return http::ConnectionPreference::close;
        }
        if (std::chrono::steady_clock::now() - connection.opened_at >= ctx.tuning.max_connection_lifetime)
        {
            log_diagnostic(
                "connection.lifetime_cap_reached",
                {
                    {"lifetime_seconds", std::to_string(ctx.tuning.max_connection_lifetime.count()), false}
            });
            return http::ConnectionPreference::close;
        }
        auto reservation = ctx.dispatcher->try_reserve_keep_alive(policy.max_connections);
        if (!reservation.has_value())
        {
            log_diagnostic("connection.keep_alive_cap_reached",
                           {
                               {"limit", std::to_string(policy.max_connections), false}
            });
            return http::ConnectionPreference::close;
        }
        connection.parked_reservation = std::move(reservation);
        return http::ConnectionPreference::keep_alive;
    }

    // A long-poll handed to the sync pool. It owns the connection from the
    // moment it is submitted; everything it needs is held by value, since the
    // round that created it may be gone by the time it runs.
    struct SyncHandoff final
    {
        ConnectionOwner connection;
        ConnectionContext ctx;
        LocalHttpRequest request;
        SyncWaitParams wait;
        sync::SyncNotifier& notifier;
        http::HttpVersion version;
        std::string connection_header;
        http::InFlightBudget::Slot user_slot;
        http::InFlightBudget::Slot device_slot;
    };

    auto run_sync_handoff(SyncHandoff& handoff) -> void
    {
        auto& runtime = handoff.ctx.runtime;
        auto& stats = handoff.ctx.stats;
        auto* const sync_pool = handoff.ctx.sync_pool;
        auto& connection = http_connection(handoff.connection);
        auto const fd = connection.fd();
        // Re-wait loop: after each notifier fire, call the handler with
        // can_wait=true. If the handler returns needs_wait the wakeup was
        // caused by an event irrelevant to this connection (e.g. another
        // user's device key upload); advance the cursor past the irrelevant
        // bump and continue polling. If it returns complete, send immediately.
        auto dispatched_result = std::optional<DispatchResult>{};
        auto client_gone = false;
        try
        {
            // Poll in 1-second slices: short enough to detect a dropped client
            // connection within one slice, and to bound shutdown
            // (request_stop()) to one slice regardless of the client timeout.
            constexpr auto poll_interval = std::chrono::milliseconds{1000U};
            auto wait_params = handoff.wait;
            auto const deadline = std::chrono::steady_clock::now() + wait_params.timeout;
            while (sync_pool->running())
            {
                auto const remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
                if (remaining.count() <= 0)
                {
                    break;
                }
                if (handoff.notifier.wait_for_change(wait_params.since_stream_ordering,
                                                     wait_params.since_sync_stream_id,
                                                     std::min(remaining, poll_interval)))
                {
                    auto interim = handle_client_server_request(runtime, handoff.request, true);
                    if (interim.status == DispatchResult::Status::complete)
                    {
                        dispatched_result = std::move(interim);
                        break;
                    }
                    wait_params = interim.wait;
                }
                else
                {
                    // Notifier did not fire (poll-slice timeout). Check whether
                    // the peer is still connected via a non-blocking peek: when
                    // the client closes (FIN or RST), recv returns 0 or a
                    // connection error, not EAGAIN, so the thread exits at once
                    // instead of waiting out the timeout. This prevents sync-pool
                    // exhaustion when clients reconnect rapidly (an SDK reset
                    // loop abandoning one long-poll every ~90 ms).
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
            // Client closed before we could respond: close without logging a
            // completed request.
            handoff.connection.reset();
            return;
        }
        auto const final_result = dispatched_result.has_value()
                                      ? std::move(*dispatched_result)
                                      : handle_client_server_request(runtime, handoff.request, false);
        ++stats.completed_requests;
        log_diagnostic("request.completed",
                       {
                           {"method",         handoff.request.method,                                       false},
                           {"target",         observability::sanitized_http_target(handoff.request.target), false},
                           {"status",         std::to_string(final_result.response.status),                 false},
                           {"response_bytes", std::to_string(final_result.response.body.size()),            false}
        });
        auto const decision = decide_connection(handoff.ctx, connection, handoff.version, handoff.connection_header);
        auto const formatted =
            format_response(final_result.response.status, final_result.response.body, final_result.response.headers,
                            decision, keep_alive_policy_for(handoff.ctx).idle_timeout_seconds);
        auto stream = make_connection_stream(connection);
        auto const written = stream != nullptr && send_all(*stream, formatted);
        stream.reset();
        if (written && decision == http::ConnectionPreference::keep_alive && handoff.ctx.dispatcher != nullptr)
        {
            // Back to the dispatcher for the next request: the next round runs
            // on a main-pool worker (pool separation preserved).
            handoff.ctx.dispatcher->park_for_next_request(std::move(handoff.connection));
            return;
        }
        handoff.connection.reset();
    }

    // Serves exactly one request round on `connection`: read the head, drain
    // the body exactly, route, write one response. Pipelined bytes past this
    // request's body stay in connection.leftover for the next round. The
    // connection's first round that gets zero bytes is a 408; a later one is a
    // client closing an idle kept-alive connection and is closed silently.
    //
    // Returns close_connection / continue_keep_alive, or transferred when a
    // long-poll was handed to the sync pool, which then owns the connection
    // (`owner` is empty on return).
    [[nodiscard]] auto serve_request_round(ConnectionContext& ctx, HttpConnection& connection, ConnectionOwner& owner)
        -> RoundOutcome
    {
        auto stream = make_connection_stream(connection);
        if (stream == nullptr)
        {
            return RoundOutcome::close_connection;
        }
        auto const head_limits = http_request_limits_for(ctx.runtime, ctx.dispatch_mode, {}, {});
        auto const head_cap = header_size_cap(head_limits);
        auto const first_request = std::exchange(connection.first_request, false);
        auto [buffer, head_end] = read_request_head(*stream, std::move(connection.leftover), head_cap);
        // std::move leaves it valid-but-unspecified; reset it. It is re-assigned
        // below with this round's surplus bytes on keep-alive paths.
        connection.leftover.clear();

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
                write_error_response(*stream, 413U, "request head too large",
                                     transport_cors_headers(ctx, origin_from_raw_head(buffer)));
            }
            else
            {
                log_diagnostic("request.rejected", {
                                                       {"status",         "408",                                  false},
                                                       {"received_bytes", std::to_string(buffer.size()),          false},
                                                       {"reason",         "request head incomplete or timed out", false}
                });
                write_error_response(*stream, 408U, "request head incomplete or timed out",
                                     transport_cors_headers(ctx, origin_from_raw_head(buffer)));
            }
            return RoundOutcome::close_connection;
        }

        auto const parse = http::parse_request_head(std::string_view{buffer.data(), head_end}, head_limits);
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
            write_error_response(
                *stream, http::request_error_status(parse.error), reason,
                transport_cors_headers(ctx, origin_from_raw_head(std::string_view{buffer.data(), head_end})));
            return RoundOutcome::close_connection;
        }

        auto const connection_header = find_header_value(parse.request, "connection");
        auto const request_limits =
            http_request_limits_for(ctx.runtime, ctx.dispatch_mode, parse.request.method, parse.request.target);
        auto body_tail = std::string{buffer.substr(head_end)};
        auto body = std::string{};
        if (parse.request.has_content_length && parse.request.content_length > 0U)
        {
            auto const expected_body_bytes = parse.request.content_length;
            auto effective_cap = body_size_cap(request_limits);
            // HTTP-1 / HTTP-6: the media upload routes may carry up to
            // max_upload_size, but only for a request whose head already
            // authenticates. Anything else is answered from the head alone,
            // before a byte of a large body is read, and the connection closed
            // (its unread body cannot be skipped).
            if (ctx.dispatch_mode == HttpDispatchMode::client_server && parse.request.method == "POST" &&
                is_media_upload_target(parse.request.target) && expected_body_bytes > effective_cap)
            {
                auto const head_only = build_local_request(parse.request, {}, ctx.peer_addr);
                if (auto const refusal = media_upload_authentication_refusal(ctx.runtime, head_only);
                    refusal.has_value())
                {
                    ++ctx.stats.rejected_requests;
                    log_diagnostic("request.rejected",
                                   {
                                       {"method",              parse.request.method,                                       false},
                                       {"target",              observability::sanitized_http_target(parse.request.target), false},
                                       {"status",              std::to_string(refusal->status),                            false},
                                       {"expected_body_bytes", std::to_string(expected_body_bytes),                        false},
                                       {"reason",              "upload body refused before authentication",                false}
                    });
                    std::ignore = send_all(*stream, format_response(refusal->status, refusal->body, refusal->headers));
                    return RoundOutcome::close_connection;
                }
                effective_cap = max_upload_bytes(ctx.runtime);
            }
            if (expected_body_bytes > effective_cap)
            {
                ++ctx.stats.rejected_requests;
                log_diagnostic("request.rejected",
                               {
                                   {"method",              parse.request.method,                                       false},
                                   {"target",              observability::sanitized_http_target(parse.request.target), false},
                                   {"status",              "413",                                                      false},
                                   {"expected_body_bytes", std::to_string(expected_body_bytes),                        false},
                                   {"limit_bytes",         std::to_string(effective_cap),                              false},
                                   {"reason",              "request body too large",                                   false}
                });
                // Matrix spec §10.5: every response MUST carry CORS headers or
                // browsers surface the 413 as a CORS error instead of the real one.
                auto const cors_hdrs = transport_cors_headers(ctx, find_header_value(parse.request, "origin"));
                auto const rejection =
                    format_response(413U, R"({"errcode":"M_TOO_LARGE","error":"request body too large"})", cors_hdrs);
                std::ignore = send_all(*stream, rejection);
                return RoundOutcome::close_connection;
            }
            // Drain the body exactly: read precisely Content-Length bytes and
            // keep any surplus (a pipelined next request) for the next round.
            auto const expected = static_cast<std::size_t>(expected_body_bytes);
            auto body_result = read_remaining_body(*stream, std::move(body_tail), expected, effective_cap, ctx.tuning);
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
                write_error_response(*stream, 408U, "request body incomplete or timed out",
                                     transport_cors_headers(ctx, find_header_value(parse.request, "origin")));
                return RoundOutcome::close_connection;
            }
            body = std::move(body_result.body);
            connection.leftover = std::move(body_result.leftover);
        }
        else
        {
            // No body declared. Chunked transfer coding is rejected by the
            // parser, so a body can only arrive via Content-Length; every
            // byte past the head therefore belongs to the next request.
            connection.leftover = std::move(body_tail);
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
            auto* const notifier = ctx.runtime.sync_notifier.get();
            if (notifier == nullptr)
            {
                write_error_response(*stream, 503U, matrix_error("M_UNKNOWN", "sync notifier unavailable"),
                                     transport_cors_headers(ctx, find_header_value(parse.request, "origin")));
                return RoundOutcome::close_connection;
            }

            // Admit before submitting: queued waits count too. One account must
            // not occupy the sync pool, even across tokens, devices and protocols.
            auto const& sync_settings = ctx.runtime.homeserver.config.server().http;
            auto const sync_caps = sync_admission_caps(
                sync_settings, ctx.sync_pool == nullptr ? std::size_t{0U} : ctx.sync_pool->worker_count());
            auto user_slot =
                ctx.runtime.sync_user_budget->try_acquire(result.wait.user_id, sync_caps.global, sync_caps.per_user);
            auto const device_key =
                std::to_string(result.wait.user_id.size()) + ":" + result.wait.user_id + result.wait.device_id;
            auto device_slot =
                user_slot.has_value()
                    ? ctx.runtime.sync_device_budget->try_acquire(device_key, sync_caps.global, sync_caps.per_device)
                    : std::nullopt;
            if (result.wait.user_id.empty() || !user_slot.has_value() || !device_slot.has_value())
            {
                write_error_response(*stream, 429U,
                                     matrix_error("M_LIMIT_EXCEEDED", "too many concurrent sync waits", 1000U),
                                     transport_cors_headers(ctx, find_header_value(parse.request, "origin")));
                return RoundOutcome::close_connection;
            }

            if (ctx.sync_pool != nullptr)
            {
                // Hand off to the dedicated sync pool: this main-pool worker is
                // freed at once, and the sync task owns the connection from
                // here (closing it, or handing it back to the dispatcher for
                // the next keep-alive round).
                auto handoff = std::make_shared<SyncHandoff>(
                    SyncHandoff{// SHARED_PTR: reviewed — copyable pool task
                                std::move(owner), ctx, local_request, result.wait, *notifier, parse.request.version,
                                connection_header, std::move(*user_slot), std::move(*device_slot)});
                if (ctx.sync_pool->submit([handoff] {
                        run_sync_handoff(*handoff);
                    }))
                {
                    return RoundOutcome::transferred;
                }
                // A refused handoff is backpressure, never a reason to wait on
                // a main request worker. Take ownership back before answering.
                owner = std::move(handoff->connection);
                write_error_response(*stream, 429U, matrix_error("M_LIMIT_EXCEEDED", "sync pool unavailable", 1000U),
                                     transport_cors_headers(ctx, find_header_value(parse.request, "origin")));
                return RoundOutcome::close_connection;
            }

            // No sync pool (embedded callers and tests): wait until new
            // events arrive or the timeout expires. The re-wait loop mirrors
            // the sync-pool path.
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
        auto const decision = decide_connection(ctx, connection, parse.request.version, connection_header);
        auto const formatted = format_response(result.response.status, result.response.body, result.response.headers,
                                               decision, keep_alive_policy_for(ctx).idle_timeout_seconds);
        if (!send_all(*stream, formatted))
        {
            return RoundOutcome::close_connection;
        }
        return decision == http::ConnectionPreference::keep_alive ? RoundOutcome::continue_keep_alive
                                                                  : RoundOutcome::close_connection;
    }

} // namespace

auto HttpConnectionDispatcher::Impl::start() -> bool
{
    if (m_parker != nullptr)
    {
        return m_parker->running();
    }
    // At most one connection per worker is out of the parker at once, so the
    // pool's queue never holds more than its workers; and one client key may
    // hold at most a quarter of them (HTTP-1). A trusted proxy's connections
    // carry an empty key and are exempt from the second cap only.
    auto const workers = std::max<std::size_t>(1U, pool.worker_count());
    auto const limits = net::ConnectionParker::Limits{workers, std::max<std::size_t>(1U, workers / 4U)};
    m_parker = std::make_unique<net::ConnectionParker>(
        limits, [weak = weak_from_this()](net::ConnectionParker::Dispatched dispatched) {
            if (auto const self = weak.lock(); self != nullptr)
            {
                self->dispatch(std::move(dispatched));
            }
        });
    return m_parker->start();
}

auto HttpConnectionDispatcher::Impl::request_stop() -> void
{
    if (m_parker != nullptr)
    {
        m_parker->request_stop();
    }
}

auto HttpConnectionDispatcher::Impl::running() const -> bool
{
    return m_parker != nullptr && m_parker->running();
}

auto HttpConnectionDispatcher::Impl::accept(core::SocketHandle socket, std::string peer_addr, HttpDispatchMode mode,
                                            ConnectionAdmission admission,
                                            std::optional<std::reference_wrapper<TlsServerContext>> tls_context) -> void
{
    ++stats.accepted_connections;
    auto owner = std::make_unique<HttpConnection>(std::move(socket), mode, std::move(peer_addr),
                                                  std::move(admission.client_key));
    auto& connection = *owner;
    if (admission.slot.has_value())
    {
        connection.connection_slot.emplace(std::move(*admission.slot));
    }
    connection.tls_handshake_owed = tls_context;
    park_awaiting_first_request(std::move(owner));
}

// A connection that has not yet sent its first request: newly accepted, or a
// TLS connection whose handshake has just completed. It must send a byte within
// the first-byte timeout, and at most listeners.max_queued_connections such
// connections wait at once (0: unbounded).
auto HttpConnectionDispatcher::Impl::park_awaiting_first_request(ConnectionOwner owner) -> void
{
    auto& connection = http_connection(owner);
    auto const cap = runtime.homeserver.config.listeners().max_queued_connections;
    auto reservation = ParkingReservation::try_acquire(m_parked_new, cap);
    if (!reservation.has_value())
    {
        log_diagnostic("connection.pending_cap_reached", {
                                                             {"cap", std::to_string(cap), false}
        });
        return; // ~owner closes it
    }
    connection.parked_reservation = std::move(reservation);
    auto key = connection.client_key;
    if (!m_parker->park(std::move(owner), std::move(key), std::chrono::steady_clock::now() + tuning.first_byte_timeout))
    {
        log_diagnostic("connection.refused_stopping", {});
    }
}

auto HttpConnectionDispatcher::Impl::park_for_next_request(ConnectionOwner owner) -> void
{
    auto& connection = http_connection(owner);
    auto const idle = std::chrono::seconds{runtime.homeserver.config.server().http.keep_alive_idle_seconds};
    auto key = connection.client_key;
    // A stopped parker closes the connection: shutdown in progress.
    std::ignore = m_parker->park(std::move(owner), std::move(key), std::chrono::steady_clock::now() + idle);
}

// On the parker thread, with no lock held. The job is shared only because pool
// tasks are copyable std::functions; exactly one task runs it.
auto HttpConnectionDispatcher::Impl::dispatch(net::ConnectionParker::Dispatched dispatched) -> void
{
    auto job = std::make_shared<net::ConnectionParker::Dispatched>( // SHARED_PTR: reviewed — copyable pool task
        std::move(dispatched));
    auto self = shared_from_this();
    if (!pool.submit([self, job] {
            self->serve(std::move(*job));
        }))
    {
        // Only when the pool is stopping: the parker never has more
        // connections out than the pool has workers. ~job closes it.
        log_diagnostic("connection.dispatch_refused", {});
    }
}

// On a pool worker. `dispatched.share` is this connection's claim on the
// worker caps; it is released when this returns, whichever way.
auto HttpConnectionDispatcher::Impl::serve(net::ConnectionParker::Dispatched dispatched) -> void
{
    auto owner = std::move(dispatched.connection);
    auto& connection = http_connection(owner);
    // No longer parked: its parking slot goes back.
    connection.parked_reservation.reset();
    if (connection.tls_handshake_owed.has_value())
    {
        // The ClientHello is readable; the handshake is bounded by the
        // handshake timeout and counts against the client's worker share.
        auto& tls_context = connection.tls_handshake_owed->get();
        connection.tls_handshake_owed.reset();
        auto accepted = accept_tls_connection(tls_context, connection.fd(), receive_timeout_milliseconds);
        if (!accepted.ok())
        {
            ++stats.rejected_requests;
            log_diagnostic("tls.handshake.rejected", {
                                                         {"reason", accepted.error, false}
            });
            return; // ~owner closes it
        }
        connection.tls.emplace(std::move(*accepted.connection));
        park_awaiting_first_request(std::move(owner));
        return;
    }
    auto ctx =
        ConnectionContext{runtime, stats, sync_pool, shared_from_this(), tuning, connection.mode, connection.peer_addr};
    switch (serve_request_round(ctx, connection, owner))
    {
    case RoundOutcome::close_connection:
        return; // ~owner closes it
    case RoundOutcome::continue_keep_alive:
        park_for_next_request(std::move(owner));
        return;
    case RoundOutcome::transferred:
        return; // the sync-pool task owns it
    }
}

HttpConnectionDispatcher::HttpConnectionDispatcher(ClientServerRuntime& runtime, HttpServeStats& stats,
                                                   net::ThreadPool& pool, net::ThreadPool* sync_pool,
                                                   HttpServeTuning tuning)
    : m_impl{std::make_shared<Impl>(runtime, stats, pool, sync_pool, tuning)}
{
}

HttpConnectionDispatcher::~HttpConnectionDispatcher()
{
    m_impl->request_stop();
}

auto HttpConnectionDispatcher::start() -> bool
{
    return m_impl->start();
}

auto HttpConnectionDispatcher::request_stop() -> void
{
    m_impl->request_stop();
}

auto HttpConnectionDispatcher::running() const -> bool
{
    return m_impl->running();
}

auto HttpConnectionDispatcher::impl() noexcept -> Impl&
{
    return *m_impl;
}

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
    // per-call contract: with no dispatcher there is nowhere to park the
    // connection, so keep-alive is off (see keep_alive_policy_for) and this
    // serves a single round. The caller owns the descriptor unless it was
    // transferred to the sync pool, which then closes it.
    auto owner = ConnectionOwner{std::make_unique<HttpConnection>(core::SocketHandle{client_fd}, dispatch_mode,
                                                                  std::string{peer_addr}, std::string{})};
    auto& connection = http_connection(owner);
    auto ctx =
        ConnectionContext{runtime, stats, sync_pool, nullptr, HttpServeTuning{}, dispatch_mode, std::string{peer_addr}};
    if (serve_request_round(ctx, connection, owner) == RoundOutcome::transferred)
    {
        return true;
    }
    // Not ours to close: give the descriptor back to the caller untouched.
    std::ignore = connection.socket.release();
    return false;
}

namespace
{

    // Accepts connections until `shutdown` fires, the acceptor fails, or the
    // dispatcher stops, and parks each admitted one on the dispatcher. No
    // worker is involved: a connection reaches the pool only once it is
    // readable.
    auto accept_until_shutdown(net::TcpAcceptor& acceptor, HttpConnectionDispatcher::Impl& dispatcher,
                               net::ShutdownSignal& shutdown, HttpDispatchMode dispatch_mode,
                               std::optional<std::reference_wrapper<TlsServerContext>> tls_context) -> void
    {
        auto const event_prefix = std::string{tls_context.has_value() ? "tls.connection." : "connection."};
        while (!shutdown.fired() && acceptor.valid() && dispatcher.running())
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
            //
            // SOCK_NONBLOCK: the socket is non-blocking from the instant it
            // exists, as ADR-0054 requires for the life of the connection; the
            // TLS handshake keeps it that way.
            auto raw_client = ::accept4(acceptor.fd(), reinterpret_cast<sockaddr*>(&peer_sa), &peer_len,
                                        SOCK_CLOEXEC | SOCK_NONBLOCK);
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
                    log_diagnostic(event_prefix + "accept_retry", {
                                                                      {"errno", std::to_string(errno), false}
                    });
                    ::usleep(100000);
                    continue;
                }
                log_diagnostic(event_prefix + "accept_failed", {
                                                                   {"errno", std::to_string(errno), false}
                });
                return;
            }
            auto client = core::SocketHandle{raw_client};
            auto peer_addr = peer_addr_to_string(peer_sa);
            // ADR-0072: refuse before reading a byte (or starting a TLS
            // handshake) once this client holds its share of connections;
            // ~SocketHandle closes the refused descriptor.
            auto admission = admit_connection(dispatcher.runtime, peer_addr);
            if (!admission.admitted)
            {
                log_diagnostic(
                    event_prefix + "per_ip_cap_reached",
                    {
                        {"cap",
                         std::to_string(dispatcher.runtime.homeserver.config.server().http.max_connections_per_ip),
                         false}
                });
                continue;
            }
            dispatcher.accept(std::move(client), std::move(peer_addr), dispatch_mode, std::move(admission),
                              tls_context);
        }
    }

} // namespace

auto serve_http(net::TcpAcceptor& acceptor, HttpConnectionDispatcher& dispatcher, net::ShutdownSignal& shutdown,
                HttpDispatchMode dispatch_mode) -> void
{
    accept_until_shutdown(acceptor, dispatcher.impl(), shutdown, dispatch_mode, std::nullopt);
}

auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, HttpConnectionDispatcher& dispatcher,
                    net::ShutdownSignal& shutdown, HttpDispatchMode dispatch_mode) -> void
{
    accept_until_shutdown(acceptor, dispatcher.impl(), shutdown, dispatch_mode, std::ref(tls_context));
}

auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, net::ShutdownSignal& shutdown,
                HttpServeStats& stats, HttpDispatchMode dispatch_mode, net::ThreadPool& pool,
                net::ThreadPool* sync_pool, HttpServeTuning tuning) -> void
{
    auto dispatcher = HttpConnectionDispatcher{runtime, stats, pool, sync_pool, tuning};
    if (!dispatcher.start())
    {
        log_diagnostic("dispatcher.start_failed", {}, observability::LogEventSeverity::error);
        return;
    }
    serve_http(acceptor, dispatcher, shutdown, dispatch_mode);
    dispatcher.request_stop();
}

auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode,
                    net::ThreadPool& pool, net::ThreadPool* sync_pool, HttpServeTuning tuning) -> void
{
    auto dispatcher = HttpConnectionDispatcher{runtime, stats, pool, sync_pool, tuning};
    if (!dispatcher.start())
    {
        log_diagnostic("dispatcher.start_failed", {}, observability::LogEventSeverity::error);
        return;
    }
    serve_tls_http(tls_context, acceptor, dispatcher, shutdown, dispatch_mode);
    dispatcher.request_stop();
}

} // namespace merovingian::homeserver
