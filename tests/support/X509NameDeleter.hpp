// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <openssl/x509.h>

namespace merovingian::tests::tls_mock
{

struct X509NameDeleter final
{
    auto operator()(X509_NAME* name) const noexcept -> void
    {
        X509_NAME_free(name);
    }
};

} // namespace merovingian::tests::tls_mock
