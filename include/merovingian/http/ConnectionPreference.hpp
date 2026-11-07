// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

// Whether the server should hold the connection open after writing a response
// or close it. `close` matches the historical one-request-per-connection
// behaviour; `keep_alive` emits `Connection: keep-alive` (plus a
// `Keep-Alive: timeout=N` hint) and parks the connection for the next request.
enum class ConnectionPreference : std::uint8_t
{
    close,
    keep_alive,
};

} // namespace merovingian::http
