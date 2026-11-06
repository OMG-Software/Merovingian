// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::database
{

// A third-party identifier (3PID) bound to a user account. `medium` is "email"
// or "msisdn"; `address` is the normalized identifier. `country` and
// `id_server` are nullopt when the binding was added without an identity-server
// round-trip (e.g. a registration-time validated email); `id_server` is set
// once the 3PID is bound at an identity server and `bound` records that the
// server-side IS binding exists. `added_at_ms`/`validated_at_ms` are epoch-ms.
// Primary key is (user_id, medium, address); a 3PID is globally unique to one
// account (enforced by threepid_in_use before insert).
struct PersistentThreePidBinding final
{
    std::string user_id{};
    std::string medium{};
    std::string address{};
    std::optional<std::string> country{};
    std::optional<std::string> id_server{};
    std::uint64_t added_at_ms{0U};
    std::uint64_t validated_at_ms{0U};
    bool bound{false};
    // IS validation pair (populated only for 3PIDs bound via a remote identity
    // server). Stored so a later unbind can drive IS auth mode 2 (sid +
    // client_secret) without a homeserver-signed request. See migration 007 and
    // docs/threat-model.md for the storage trade-off.
    std::optional<std::string> client_secret{};
    std::optional<std::string> sid{};
};

} // namespace merovingian::database
