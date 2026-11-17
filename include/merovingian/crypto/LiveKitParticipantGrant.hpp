// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::crypto
{

// What a LiveKit participant token says (ADR-0828). The token always grants `roomJoin` and `canSubscribe` in `room`
// and nothing else but what is here: there is no field for `roomCreate`, `roomAdmin`, `roomList`, `roomRecord`,
// `ingressAdmin`, `hidden`, `canUpdateOwnMetadata`, a name, metadata or attributes, so no token built from this type can
// carry them.
struct LiveKitParticipantGrant final
{
    // The MSC4195 participant identity and room name: unpadded standard base64 of a SHA-256, 43 characters each.
    std::string identity{};
    std::string room{};
    // `canPublish` and `canPublishData` together.
    bool can_publish{false};
    // Seconds since the Unix epoch. `expires` is after `not_before`.
    std::int64_t not_before{0};
    std::int64_t expires{0};
};

} // namespace merovingian::crypto
