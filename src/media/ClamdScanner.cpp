// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/ClamdScanner.hpp"

#include "merovingian/core/FileDescriptor.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace merovingian::media
{
namespace
{

    using Clock = std::chrono::steady_clock;

    // clamd's INSTREAM reply is one short line; anything longer is not a reply this client understands.
    constexpr std::size_t max_reply_bytes = 512U;
    constexpr std::size_t max_detail_bytes = 128U;
    // Bytes per INSTREAM chunk. clamd accepts any chunk up to its StreamMaxLength.
    constexpr std::size_t chunk_bytes = 64U * 1024U;
    constexpr auto capacity_poll_interval = std::chrono::milliseconds{5};

    constexpr std::string_view instream_command{"zINSTREAM\0", 10U};
    constexpr std::string_view reply_prefix{"stream: "};
    constexpr std::string_view found_suffix{" FOUND"};
    constexpr std::string_view clean_reply{"stream: OK"};

    [[nodiscard]] auto result_of(ClamdVerdict verdict, std::string detail) -> ClamdScanResult
    {
        return {verdict, std::move(detail)};
    }

    // Printable ASCII only, capped: clamd's text reaches logs and the audit table.
    [[nodiscard]] auto sanitise_detail(std::string_view text) -> std::string
    {
        auto cleaned = std::string{};
        for (auto const c : text.substr(0U, max_detail_bytes))
        {
            cleaned.push_back(c >= 0x20 && c < 0x7F ? c : '?');
        }
        return cleaned;
    }

    [[nodiscard]] auto errno_text(int const error) -> std::string
    {
        return std::strerror(error);
    }

    // Milliseconds until `deadline`, 0 when it has passed.
    [[nodiscard]] auto remaining_ms(Clock::time_point const deadline) -> int
    {
        auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        return left <= 0 ? 0 : static_cast<int>(std::min<std::int64_t>(left, INT_MAX));
    }

    // True when `fd` reports `events` (or an error or hang-up, which the next call then reports) before `deadline`.
    [[nodiscard]] auto wait_for(int const fd, short const events, Clock::time_point const deadline) -> bool
    {
        while (true)
        {
            auto descriptor = pollfd{fd, events, 0};
            auto const ready = ::poll(&descriptor, 1, remaining_ms(deadline));
            if (ready > 0)
            {
                return true;
            }
            if (ready == 0 || errno != EINTR)
            {
                return false;
            }
        }
    }

    [[nodiscard]] auto connect_to(std::string const& path, Clock::time_point const deadline, std::string& error)
        -> core::FileDescriptor
    {
        auto address = sockaddr_un{};
        if (path.empty() || path.size() >= sizeof(address.sun_path))
        {
            error = std::string{"socket path does not fit sockaddr_un"};
            return core::FileDescriptor{};
        }
        auto descriptor = core::FileDescriptor{::socket(AF_UNIX, SOCK_STREAM, 0)};
        if (!descriptor.valid())
        {
            error = "socket: " + errno_text(errno);
            return core::FileDescriptor{};
        }
        // Close-on-exec first: the thumbnail worker is spawned from this process.
        if (!descriptor.set_cloexec())
        {
            error = std::string{"cannot set close-on-exec"};
            return core::FileDescriptor{};
        }
        auto const flags = ::fcntl(descriptor.get(), F_GETFL, 0);
        if (flags < 0 || ::fcntl(descriptor.get(), F_SETFL, flags | O_NONBLOCK) != 0)
        {
            error = std::string{"cannot set non-blocking mode"};
            return core::FileDescriptor{};
        }
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, path.data(), path.size());
        auto const length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1U);
        if (::connect(descriptor.get(), reinterpret_cast<sockaddr const*>(&address), length) == 0)
        {
            return descriptor;
        }
        if (errno != EINPROGRESS)
        {
            // EAGAIN here is a full listen backlog on Linux: clamd is saturated, so this is a failure, not a retry.
            error = "connect: " + errno_text(errno);
            return core::FileDescriptor{};
        }
        if (!wait_for(descriptor.get(), POLLOUT, deadline))
        {
            error = std::string{"connect timed out"};
            return core::FileDescriptor{};
        }
        auto socket_error = 0;
        auto socket_error_length = static_cast<socklen_t>(sizeof(socket_error));
        if (::getsockopt(descriptor.get(), SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_length) != 0 ||
            socket_error != 0)
        {
            error = "connect: " + errno_text(socket_error);
            return core::FileDescriptor{};
        }
        return descriptor;
    }

    [[nodiscard]] auto send_all(int const fd, std::string_view data, Clock::time_point const deadline) -> std::string
    {
        while (!data.empty())
        {
            auto const sent = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
            if (sent > 0)
            {
                data.remove_prefix(static_cast<std::size_t>(sent));
                continue;
            }
            if (sent < 0 && errno == EINTR)
            {
                continue;
            }
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if (!wait_for(fd, POLLOUT, deadline))
                {
                    return std::string{"timed out sending the stream"};
                }
                continue;
            }
            return "send: " + errno_text(sent < 0 ? errno : EPIPE);
        }
        return {};
    }

    // Sends the INSTREAM command, the bytes in length-prefixed chunks, and the zero-length terminator.
    [[nodiscard]] auto send_stream(int const fd, std::string_view bytes, Clock::time_point const deadline)
        -> std::string
    {
        if (auto const sent = send_all(fd, instream_command, deadline); !sent.empty())
        {
            return sent;
        }
        auto frame = std::string{};
        frame.reserve(4U + chunk_bytes);
        while (!bytes.empty())
        {
            auto const chunk = bytes.substr(0U, chunk_bytes);
            auto const length = static_cast<std::uint32_t>(chunk.size());
            frame.clear();
            frame.push_back(static_cast<char>((length >> 24U) & 0xFFU));
            frame.push_back(static_cast<char>((length >> 16U) & 0xFFU));
            frame.push_back(static_cast<char>((length >> 8U) & 0xFFU));
            frame.push_back(static_cast<char>(length & 0xFFU));
            frame.append(chunk);
            if (auto const sent = send_all(fd, frame, deadline); !sent.empty())
            {
                return sent;
            }
            bytes.remove_prefix(chunk.size());
        }
        return send_all(fd, std::string_view{"\0\0\0\0", 4U}, deadline);
    }

    // Reads the reply up to its NUL terminator. A reply without one, or a longer one, is malformed.
    [[nodiscard]] auto read_reply(int const fd, Clock::time_point const deadline, std::string& reply) -> std::string
    {
        auto buffer = std::array<char, 128U>{};
        while (true)
        {
            if (!wait_for(fd, POLLIN, deadline))
            {
                return std::string{"timed out waiting for the reply"};
            }
            auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
            if (received < 0)
            {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    continue;
                }
                return "recv: " + errno_text(errno);
            }
            if (received == 0)
            {
                return std::string{"clamd closed the connection before it finished its reply"};
            }
            auto const view = std::string_view{buffer.data(), static_cast<std::size_t>(received)};
            auto const terminator = view.find('\0');
            reply.append(view.substr(0U, terminator));
            if (reply.size() > max_reply_bytes)
            {
                return std::string{"clamd reply is too long"};
            }
            if (terminator != std::string_view::npos)
            {
                return {};
            }
        }
    }

    // `stream: OK` is clean and `stream: <name> FOUND` infected; everything else (an ERROR line, a size-limit
    // message, anything unexpected) is a failed scan.
    [[nodiscard]] auto classify_reply(std::string_view reply) -> ClamdScanResult
    {
        while (!reply.empty() && (reply.back() == '\n' || reply.back() == '\r'))
        {
            reply.remove_suffix(1U);
        }
        if (reply.starts_with(reply_prefix) && reply.ends_with(found_suffix) &&
            reply.size() > reply_prefix.size() + found_suffix.size())
        {
            auto const name =
                reply.substr(reply_prefix.size(), reply.size() - reply_prefix.size() - found_suffix.size());
            return result_of(ClamdVerdict::infected, sanitise_detail(name));
        }
        if (reply == clean_reply)
        {
            return result_of(ClamdVerdict::clean, {});
        }
        return result_of(ClamdVerdict::failed, "unexpected clamd reply: " + sanitise_detail(reply));
    }

    // Holds one place of the scanner's concurrency bound and gives it back on every path.
    class ScanSlot final
    {
    public:
        explicit ScanSlot(std::atomic<std::uint32_t>& counter) noexcept
            : m_counter{counter}
        {
        }
        ScanSlot(ScanSlot const&) = delete;
        auto operator=(ScanSlot const&) -> ScanSlot& = delete;
        ScanSlot(ScanSlot&&) = delete;
        auto operator=(ScanSlot&&) -> ScanSlot& = delete;
        ~ScanSlot()
        {
            m_counter.fetch_sub(1U, std::memory_order_acq_rel);
        }

    private:
        std::atomic<std::uint32_t>& m_counter;
    };

} // namespace

ClamdScanner::ClamdScanner(ClamdScannerSettings settings)
    : m_settings{std::move(settings)}
{
}

auto ClamdScanner::enabled() const noexcept -> bool
{
    return m_settings.enabled();
}

auto ClamdScanner::settings() const noexcept -> ClamdScannerSettings const&
{
    return m_settings;
}

auto ClamdScanner::in_flight() const noexcept -> std::uint32_t
{
    return m_in_flight.load(std::memory_order_acquire);
}

auto ClamdScanner::scan(std::string_view const bytes) -> ClamdScanResult
{
    if (!enabled())
    {
        return result_of(ClamdVerdict::failed, "clamd scanning is not configured");
    }
    if (bytes.size() > m_settings.max_scan_bytes)
    {
        return result_of(ClamdVerdict::oversize, "larger than clamd_max_scan_size");
    }
    auto const deadline = Clock::now() + std::chrono::milliseconds{m_settings.timeout_ms};

    // Take a place before touching the socket, waiting for one until the deadline: a slow clamd must not let every
    // request thread hold a connection to it.
    auto const limit = std::max(1U, m_settings.max_concurrent);
    while (true)
    {
        auto current = m_in_flight.load(std::memory_order_acquire);
        if (current < limit)
        {
            if (m_in_flight.compare_exchange_weak(current, current + 1U, std::memory_order_acq_rel))
            {
                break;
            }
            continue;
        }
        if (Clock::now() >= deadline)
        {
            return result_of(ClamdVerdict::failed, "no scan capacity before the deadline");
        }
        std::this_thread::sleep_for(capacity_poll_interval);
    }
    auto const slot = ScanSlot{m_in_flight};

    auto error = std::string{};
    auto const connection = connect_to(m_settings.socket_path, deadline, error);
    if (!connection.valid())
    {
        return result_of(ClamdVerdict::failed, sanitise_detail(error));
    }
    if (auto const sent = send_stream(connection.get(), bytes, deadline); !sent.empty())
    {
        return result_of(ClamdVerdict::failed, sanitise_detail(sent));
    }
    auto reply = std::string{};
    if (auto const received = read_reply(connection.get(), deadline, reply); !received.empty())
    {
        return result_of(ClamdVerdict::failed, sanitise_detail(received));
    }
    return classify_reply(reply);
}

auto clamd_supported_on_this_platform() noexcept -> bool
{
#if defined(__FreeBSD__) || defined(__OpenBSD__)
    return false;
#else
    return true;
#endif
}

} // namespace merovingian::media
