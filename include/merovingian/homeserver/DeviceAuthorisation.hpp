// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/DeviceAuthorisationState.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// One device authorisation (`POST /_merovingian/oauth2/device`, RFC 8628 section 3.1; plan P11; ADR-0804), held by
// `DeviceAuthorisationStore` under the hash of its device code. The store sets every field from its own arguments.
struct DeviceAuthorisation final
{
    // The registered client that asked, and the scope it was granted (`oauth::parse_scope`, canonical order) with the
    // device ID that scope names.
    std::string client_id{};
    std::string scope{};
    std::string device_id{};
    // The user code in its stored form (eight alphabet characters), shown on the consent page.
    std::string user_code{};
    // The rate-limit client key of the device's request (`rate_limit_client_key`).
    std::string client_address_key{};
    std::uint64_t created_at_ms{0U};
    std::uint64_t expires_at_ms{0U};
    // The polling interval the device must keep; `slow_down` adds five seconds to it (RFC 8628 section 3.5).
    std::uint64_t interval_ms{0U};
    // When the device last polled and was answered `authorization_pending` or `slow_down`; none before its first poll.
    std::optional<std::uint64_t> last_poll_ms{};
    DeviceAuthorisationState state{DeviceAuthorisationState::pending};
    // The user who approved or denied; empty while pending.
    std::string user_id{};
};

} // namespace merovingian::homeserver
