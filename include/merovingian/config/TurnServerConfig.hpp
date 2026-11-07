// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

struct TurnServerConfig final
{
    // TURN server URI advertised to clients, e.g. "turn:turn.example.org:3478?transport=udp".
    // When empty the TURN endpoint returns an empty object so VoIP clients
    // gracefully disable relay support.
    std::string server{};
    // Static credentials issued to every authenticated client, for a TURN server that takes one shared account
    // or none. Mutually exclusive with shared_secret_file.
    std::string username{};
    std::string password{};
    // The coturn `static-auth-secret` of a TURN server run with `use-auth-secret` (ADR-0480): an owner-only file
    // holding it (0400, first line). With it set each client gets its own time-limited credentials
    // (`<expiry>:<user_id>` and the base64 HMAC-SHA1 of that), good for ttl_seconds. Read on each request into a
    // SecretBuffer, never logged. Mutually exclusive with username and password.
    std::string shared_secret_file{};
    // Lifetime in seconds advertised in the response. Defaults to 24 hours.
    std::uint32_t ttl_seconds{86400U};
};

} // namespace merovingian::config
