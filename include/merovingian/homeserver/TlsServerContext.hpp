// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

struct ssl_ctx_st;

namespace merovingian::homeserver
{

struct TlsServerContextResult;

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

} // namespace merovingian::homeserver
