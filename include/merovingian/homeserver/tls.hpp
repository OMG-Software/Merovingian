// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

struct ssl_ctx_st;
struct ssl_st;

namespace merovingian::homeserver
{

struct TlsServerContextResult;
struct TlsConnectionResult;

class TlsServerContext final
{
public:
    TlsServerContext() = delete;
    ~TlsServerContext();

    TlsServerContext(TlsServerContext const&) = delete;
    auto operator=(TlsServerContext const&) -> TlsServerContext& = delete;

    TlsServerContext(TlsServerContext&& other) noexcept;
    auto operator=(TlsServerContext&& other) noexcept -> TlsServerContext&;

    [[nodiscard]] auto native_handle() const noexcept -> ssl_ctx_st&;

private:
    explicit TlsServerContext(ssl_ctx_st& context) noexcept;

    ssl_ctx_st* m_context;

    friend struct TlsServerContextResult;
    friend auto make_tls_server_context(std::string const& certificate_file, std::string const& private_key_file)
        -> TlsServerContextResult;
};

struct TlsServerContextResult final
{
    std::optional<TlsServerContext> context{};
    std::string error{};

    [[nodiscard]] auto ok() const noexcept -> bool;
};

class TlsConnection final
{
public:
    TlsConnection() = delete;
    ~TlsConnection();

    TlsConnection(TlsConnection const&) = delete;
    auto operator=(TlsConnection const&) -> TlsConnection& = delete;

    TlsConnection(TlsConnection&& other) noexcept;
    auto operator=(TlsConnection&& other) noexcept -> TlsConnection&;

    [[nodiscard]] auto fd() const noexcept -> int;
    [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t;
    [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t;

private:
    TlsConnection(ssl_st& connection, int file_descriptor) noexcept;

    ssl_st* m_connection;
    int m_fd;

    friend struct TlsConnectionResult;
    friend auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds)
        -> TlsConnectionResult;
};

struct TlsConnectionResult final
{
    std::optional<TlsConnection> connection{};
    std::string error{};

    [[nodiscard]] auto ok() const noexcept -> bool;
};

[[nodiscard]] auto make_tls_server_context(std::string const& certificate_file, std::string const& private_key_file)
    -> TlsServerContextResult;

[[nodiscard]] auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds)
    -> TlsConnectionResult;

} // namespace merovingian::homeserver
