// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/tcp_acceptor.hpp"

#include "merovingian/core/file_descriptor.hpp"

#include <cerrno>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace merovingian::net
{
namespace
{

    constexpr auto listen_backlog = 128;

    [[nodiscard]] auto error_message(int code) -> std::string
    {
        auto const* text = std::strerror(code);
        return text == nullptr ? std::string{"unknown error"} : std::string{text};
    }

    [[nodiscard]] auto extract_port(sockaddr_storage const& storage) noexcept -> std::uint16_t
    {
        if (storage.ss_family == AF_INET)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const& v4 = reinterpret_cast<sockaddr_in const&>(storage);
            return ntohs(v4.sin_port);
        }
        if (storage.ss_family == AF_INET6)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const& v6 = reinterpret_cast<sockaddr_in6 const&>(storage);
            return ntohs(v6.sin6_port);
        }
        return 0U;
    }

} // namespace

auto TcpAcceptor::bind(std::string_view host, std::uint16_t port) -> TcpBindResult
{
    close();

    auto hints = addrinfo{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    auto const host_string = std::string{host};
    auto const port_string = std::to_string(port);
    auto* results = static_cast<addrinfo*>(nullptr);
    auto const resolve_status = ::getaddrinfo(host_string.c_str(), port_string.c_str(), &hints, &results);
    if (resolve_status != 0 || results == nullptr)
    {
        auto reason = std::string{gai_strerror(resolve_status)};
        if (results != nullptr)
        {
            ::freeaddrinfo(results);
        }
        return {false, "address resolution failed: " + reason};
    }

    auto last_error = std::string{};
    for (auto* candidate = results; candidate != nullptr; candidate = candidate->ai_next)
    {
        auto raw_fd = ::socket(candidate->ai_family, candidate->ai_socktype | SOCK_CLOEXEC, candidate->ai_protocol);
        if (raw_fd < 0)
        {
            last_error = "socket() failed: " + error_message(errno);
            continue;
        }
        auto handle = core::SocketHandle{raw_fd};

        auto const reuse = 1;
        if (::setsockopt(handle.native_handle(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0)
        {
            last_error = "setsockopt(SO_REUSEADDR) failed: " + error_message(errno);
            continue;
        }

        if (candidate->ai_family == AF_INET6)
        {
            auto const v6_only = 1;
            // Restrict v6 binds to v6 to avoid silently shadowing a separate v4 bind.
            static_cast<void>(
                ::setsockopt(handle.native_handle(), IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)));
        }

        if (::bind(handle.native_handle(), candidate->ai_addr, candidate->ai_addrlen) != 0)
        {
            last_error = "bind() failed: " + error_message(errno);
            continue;
        }
        if (::listen(handle.native_handle(), listen_backlog) != 0)
        {
            last_error = "listen() failed: " + error_message(errno);
            continue;
        }

        auto bound = sockaddr_storage{};
        auto bound_length = socklen_t{sizeof(bound)};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (::getsockname(handle.native_handle(), reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0)
        {
            last_error = "getsockname() failed: " + error_message(errno);
            continue;
        }

        m_socket = std::move(handle);
        m_bound_port = extract_port(bound);
        ::freeaddrinfo(results);
        return {true, {}};
    }

    ::freeaddrinfo(results);
    if (last_error.empty())
    {
        last_error = "no usable address";
    }
    return {false, last_error};
}

auto TcpAcceptor::valid() const noexcept -> bool
{
    return m_socket.valid();
}

auto TcpAcceptor::fd() const noexcept -> int
{
    return m_socket.native_handle();
}

auto TcpAcceptor::bound_port() const noexcept -> std::uint16_t
{
    return m_bound_port;
}

auto TcpAcceptor::close() noexcept -> void
{
    m_socket = core::SocketHandle{};
    m_bound_port = 0U;
}

} // namespace merovingian::net
