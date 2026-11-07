// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::appservice
{

// Why a ping did not succeed, as the client-server ping endpoint reports it
// (Application Service API, "Pinging"): 400 M_URL_NOT_SET, 502 M_CONNECTION_FAILED,
// 502 M_BAD_STATUS and 504 M_CONNECTION_TIMEOUT.
enum class AppservicePingFailure : std::uint8_t
{
    none,
    url_not_set,
    connection_failed,
    connection_timeout,
    bad_status,
};

} // namespace merovingian::appservice
