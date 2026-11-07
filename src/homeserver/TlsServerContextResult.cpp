// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/TlsServerContextResult.hpp"

namespace merovingian::homeserver
{

auto TlsServerContextResult::ok() const noexcept -> bool
{
    return context.has_value();
}

} // namespace merovingian::homeserver
