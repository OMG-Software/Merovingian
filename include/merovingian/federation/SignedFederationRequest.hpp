// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct SignedFederationRequest final
{
    std::string method{};
    std::string target{};
    std::string origin{};
    // Destination (receiving) server name. Part of the Matrix X-Matrix signed
    // request object: the verifier rebuilds the signed payload with it, so it
    // must equal this server's own name.
    std::string destination{};
    std::string key_id{};
    std::string signature{};
    // Current wall-clock time in milliseconds. Used only to reject a request
    // signed with a remote key whose published validity window has lapsed;
    // the Matrix request-signing scheme itself carries no timestamp.
    std::uint64_t now_ts{0U};
    bool canonical_json_verified{false};
    // True when the X-Matrix request signature has already been verified by a
    // trusted upstream — the main process, over the authenticated IPC channel
    // (#323). When set, handle_inbound_federation_request skips the
    // signature-verify step and trusts the origin/key_id fields. The raw
    // signature is absent in this case; only the verified identity travels.
    bool signature_verified{false};
    std::string body{};
    // Source IP of the direct peer (or the trusted-proxy-resolved client IP),
    // copied from LocalHttpRequest::remote_addr. Used solely to budget
    // pre-authentication remote-key resolution: at that point no identity has
    // been verified, so the IP is the only thing about the sender that is not
    // simply asserted in a header. Empty in tests and on paths that do not
    // resolve keys, which the budget treats as a single shared bucket.
    std::string remote_addr{};
};

} // namespace merovingian::federation
