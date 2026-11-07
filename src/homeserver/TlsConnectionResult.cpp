// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/TlsConnectionResult.hpp"

namespace merovingian::homeserver
{

auto TlsConnectionResult::ok() const noexcept -> bool
{
    return connection.has_value();
}

} // namespace merovingian::homeserver
