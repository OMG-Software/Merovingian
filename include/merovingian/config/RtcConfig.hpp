// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

// MatrixRTC transport discovery (MSC4143, MSC4195; ADR-0822). This server never fetches or proxies anything here: it
// only tells authenticated clients where the operator's own MatrixRTC authorisation service is.
struct RtcConfig final
{
    // The HTTPS URL of an external MatrixRTC authorisation service (Element's `lk-jwt-service`) that the operator
    // runs beside a LiveKit SFU. Advertised as a `livekit` transport. Empty means no transport is configured.
    // Clients build `<service_url>/sfu/get` and `<service_url>/get_token` by appending to it. validate() refuses a
    // value that is not an absolute `https` URL with a host, no userinfo, no query, no fragment, no whitespace or
    // control character and at most 2048 bytes, or whose path ends in `/`. A URL with no path (`https://host`,
    // `https://host:8443`) is accepted.
    std::string livekit_service_url{};
};

} // namespace merovingian::config
