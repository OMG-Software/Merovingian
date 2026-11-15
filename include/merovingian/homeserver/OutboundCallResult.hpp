// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// What one outbound federation call came to. `body` is the response body on
// success and a reason otherwise; `remote_status` is the HTTP status the remote
// server answered with, or 0 when no answer arrived (discovery, transport or
// signing failure, deadline).
struct OutboundCallResult final
{
    bool ok{false};
    std::string body{};
    std::uint16_t remote_status{0U};
    // The `errcode` of a non-2xx answer's Matrix error body when it is `M_INVITE_BLOCKED` (SS7), else empty. A remote
    // body is untrusted, so only this one fixed value is carried, never the remote's text.
    std::string remote_errcode{};
    // ADR-0761: true when the destination itself gave no answer: discovery found no server, or the request got no
    // connection, no verified TLS session or no response in time. False on success, on any HTTP answer (including a
    // redirect or an oversized body) and on a refusal made here before anything was sent (policy, deadline, key).
    bool remote_unreachable{false};
};

} // namespace merovingian::homeserver
