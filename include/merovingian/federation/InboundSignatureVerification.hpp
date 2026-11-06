// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationResponse.hpp"
#include "merovingian/federation/VerifiedFederationIdentity.hpp"

namespace merovingian::federation
{

// Outcome of verifying an inbound federation request's X-Matrix signature in
// the main process. On success `accepted` is true and `identity` holds the
// authenticated peer. On failure `accepted` is false and `error` is the
// FederationResponse to return to the peer directly.
struct InboundSignatureVerification final
{
    bool accepted{false};
    VerifiedFederationIdentity identity{};
    FederationResponse error{};
};

} // namespace merovingian::federation
