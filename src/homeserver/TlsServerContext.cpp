// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/TlsServerContext.hpp"

#include <openssl/ssl.h>

#include <utility>

namespace merovingian::homeserver
{

TlsServerContext::TlsServerContext(ssl_ctx_st& context) noexcept
    : m_context{&context}
{
}

TlsServerContext::~TlsServerContext()
{
    SSL_CTX_free(m_context);
}

TlsServerContext::TlsServerContext(TlsServerContext&& other) noexcept
    : m_context{std::exchange(other.m_context, nullptr)}
{
}

auto TlsServerContext::operator=(TlsServerContext&& other) noexcept -> TlsServerContext&
{
    if (this != &other)
    {
        SSL_CTX_free(m_context);
        m_context = std::exchange(other.m_context, nullptr);
    }
    return *this;
}

auto TlsServerContext::native_handle() const noexcept -> ssl_ctx_st&
{
    return *m_context;
}

} // namespace merovingian::homeserver
