// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::http
{

// Resolved host CA trust store locations. Either field may be empty when the
// corresponding location is absent from the host.
struct SystemCaTrust final
{
    std::string bundle_file{}; // concatenated PEM bundle (libcurl CAINFO)
    std::string bundle_dir{};  // OpenSSL hashed certificate directory (CAPATH)
};

} // namespace merovingian::http
