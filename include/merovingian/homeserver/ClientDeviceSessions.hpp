// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/SignedInDevice.hpp"

#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;

// Module-internal (src/AGENTS.md "Where module-local helpers go"): the client-server side of a session's start and end,
// shared by POST /login, POST /logout and the OAuth 2.0 token and revocation endpoints. Both are defined in
// ClientServerRuntime.cpp, beside the device-list helpers they use. The caller holds runtime.homeserver.mutex; neither
// releases it or makes a network call (EDUs are queued).

// After a session was granted on (`user_id`, `device_id`): a device missing from the runtime's device list is added
// with `display_name`, and for SignedInDevice::new_session the user's own device-list change is recorded, as POST
// /login does.
auto remember_signed_in_device(ClientServerRuntime& runtime, std::string_view user_id, std::string_view device_id,
                               std::string_view display_name, SignedInDevice kind) -> void;

// Ends the session of (`user_id`, `device_id`) exactly as POST /logout does for that device (ADR-0795). The servers
// sharing a room with the user are read first, then end_device_session revokes the device's access and refresh tokens,
// deletes the device (its `oauth_sessions` row with it) and audits `audit_event`; on success the device leaves the
// runtime's device list, local users who share a room are told, and each remote server is sent `m.device_list_update`
// with `deleted: true` if the device row went. Used by OAuth 2.0 revocation and by the token endpoint when an
// authorization code is replayed.
[[nodiscard]] auto end_device_session_and_announce(ClientServerRuntime& runtime, std::string_view user_id,
                                                   std::string_view device_id, std::string_view audit_event)
    -> OperationResult;

} // namespace merovingian::homeserver
