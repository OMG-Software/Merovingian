// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/SignedInDevice.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;

// Module-internal (src/AGENTS.md "Where module-local helpers go"): the client-server side of a session's start and end,
// shared by POST /login, POST /logout, device deletion, deactivation, the OAuth 2.0 token and revocation endpoints and
// the account page. All are defined in ClientServerRuntime.cpp, beside the device-list helpers they use. The caller
// holds runtime.homeserver.mutex; only finish_account_deactivation releases it or makes a network call (EDUs are
// queued).

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

// Deletes the user's device `device_id` exactly as DELETE /devices/{deviceId} does after its User-Interactive
// Authentication (shared with the account page, ADR-0796): the servers sharing a room are read first, then
// delete_local_device revokes the device's tokens, deletes it (its `oauth_sessions` row with it) and audits
// `device.deleted`; on success the device leaves the runtime's list, local users who share a room are told, and each
// remote server is sent `m.device_list_update` with `deleted: true`. A device that is not the user's is 404, whoever
// holds it.
[[nodiscard]] auto delete_device_and_announce(ClientServerRuntime& runtime, std::string_view user_id,
                                              std::string_view device_id) -> OperationResult;

// What POST /account/deactivate does once deactivate_user_account succeeded (shared with the account page): the
// user's login tokens go and every 3PID bound at an identity server is unbound, `requested_id_server` when given,
// otherwise each binding's own. Releases `guard` (the caller's lock on runtime.mutex) around each identity-server
// call, so the caller trusts nothing it read before. Returns the spec's `id_server_unbind_result`.
[[nodiscard]] auto finish_account_deactivation(ClientServerRuntime& runtime, RuntimeLock& guard,
                                               std::string_view user_id,
                                               std::optional<std::string> const& requested_id_server)
    -> std::string_view;

} // namespace merovingian::homeserver
