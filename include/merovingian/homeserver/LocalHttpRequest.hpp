// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/Header.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

struct LocalHttpRequest final
{
    std::string method{};
    std::string target{};
    std::string access_token{};
    std::string body{};
    // Parsed request headers (e.g. "Origin", "Authorization"). Populated by
    // `build_local_request` from the wire request head. Tests construct a
    // request directly and set this field to drive CORS logic.
    std::vector<http::Header> headers{};
    // Source IP address of the direct TCP peer (e.g. "192.0.2.1" or
    // "::1"). Set by the HTTP acceptor from getpeername(). Empty in
    // tests that do not exercise transport-level peer resolution.
    // Per-IP limits never key on it directly: see rate_limit_client_key.
    std::string remote_addr{};
    // #323: when sig_verified is true, the X-Matrix request signature was
    // already verified by the main process over the authenticated IPC channel
    // and verified_origin/verified_key_id carry the authenticated peer identity.
    // access_token is empty in that case and Authorization headers are stripped
    // from `headers` before the frame crosses IPC, so a compromised worker
    // cannot harvest the peer's reusable credential. The worker builds a
    // SignedFederationRequest directly from these fields and skips re-verification.
    bool sig_verified{false};
    std::string verified_origin{};
    std::string verified_key_id{};
    // Application Service API, "Timestamp massaging": the `ts` an application service appended to
    // PUT /rooms/{roomId}/send/... or PUT /rooms/{roomId}/state/..., already validated, to become the
    // event's origin_server_ts. Set only by the client-server dispatcher after it has matched an
    // as_token; it is never read from the wire, so no other caller can set it.
    std::optional<std::int64_t> origin_server_ts{};
};

} // namespace merovingian::homeserver
