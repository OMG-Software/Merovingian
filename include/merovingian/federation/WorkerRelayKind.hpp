// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

// A worker-to-main relay that reaches data the federation worker's own database role may not read or write, and so
// is admitted only against a digest main computed from the verified request it forwarded (GHSA-3p5v-vrg8-f545,
// ADR-0595). Each kind is part of its digest, so a digest made for one kind is never accepted for another.
enum class WorkerRelayKind : std::uint8_t
{
    // POST /user/keys/claim: the claim deletes the one-time keys it returns. Argument: the request body.
    otk_claim,
    // POST /user/keys/query. Argument: the request body.
    device_keys_query,
    // GET /user/devices/{userId}. Argument: the percent-decoded user ID from the path.
    user_devices,
    // GET /query/profile. Argument: the percent-decoded `user_id` query parameter.
    profile_query,
    // POST /rtc/livekit/get_token (ADR-0831): main mints a token with the LiveKit secret, which no worker holds.
    // Argument: the request body. The relay frame also names the verified origin, which main checks against the
    // pending request's.
    livekit_token,
};

} // namespace merovingian::federation
