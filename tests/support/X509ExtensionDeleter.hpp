// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <openssl/x509.h>

namespace merovingian::tests::tls_mock
{

struct X509ExtensionDeleter final
{
    auto operator()(X509_EXTENSION* extension) const noexcept -> void
    {
        X509_EXTENSION_free(extension);
    }
};

} // namespace merovingian::tests::tls_mock
