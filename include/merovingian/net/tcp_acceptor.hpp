// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/socket_handle.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::net
{

struct TcpBindResult final
{
    bool ok{false};
    std::string error{};
};

class TcpAcceptor final
{
public:
    TcpAcceptor() = default;

    TcpAcceptor(TcpAcceptor const&) = delete;
    auto operator=(TcpAcceptor const&) -> TcpAcceptor& = delete;

    TcpAcceptor(TcpAcceptor&&) noexcept = default;
    auto operator=(TcpAcceptor&&) noexcept -> TcpAcceptor& = default;

    ~TcpAcceptor() = default;

    [[nodiscard]] auto bind(std::string_view host, std::uint16_t port) -> TcpBindResult;

    [[nodiscard]] auto valid() const noexcept -> bool;
    [[nodiscard]] auto fd() const noexcept -> int;
    [[nodiscard]] auto bound_port() const noexcept -> std::uint16_t;

    auto close() noexcept -> void;

private:
    core::SocketHandle m_socket{};
    std::uint16_t m_bound_port{0U};
};

} // namespace merovingian::net
