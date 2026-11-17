// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// The built-in MatrixRTC token service (MSC4195; ADR-0829): this server issues LiveKit tokens for the operator's
// LiveKit SFU itself. Off unless all of `url`, `api_url`, `api_key` and `api_secret_file` are set; validate() refuses
// a partial set, and refuses it together with `server.rtc.livekit.service_url`, so a validated config with `url` set
// has the service on. Every key is read at start-up, so a change needs a restart.
struct LiveKitTokenServiceConfig final
{
    // `server.rtc.livekit.url`: the SFU's WebSocket URL, sent to clients as the transport's `url` and the only `url` a
    // token request may name. An absolute `wss` URL with a host, no userinfo, query or fragment, a path that does not
    // end in `/`, at most 2048 bytes.
    std::string url{};
    // `server.rtc.livekit.api_url`: where this server calls LiveKit's room service. `https`, or `http` to a loopback IP
    // literal (`127.0.0.1`, `[::1]`) when LiveKit runs on the same host; otherwise the same rules as `url`.
    std::string api_url{};
    // `server.rtc.livekit.api_key`: the API key, written as each token's `iss`. 1 to 128 ASCII letters, digits, `_`,
    // `-` and `.`.
    std::string api_key{};
    // `server.rtc.livekit.api_secret_file`: an owner-only (0400) file holding the API secret, at least 32 bytes on its
    // first line. Read for each use into a `core::SecretBuffer` and never kept.
    std::string api_secret_file{};
    // `server.rtc.livekit.token_lifetime`: how long an issued token can be used to join. 60 to 3600 seconds.
    std::uint32_t token_lifetime_seconds{3600U};
};

} // namespace merovingian::config
