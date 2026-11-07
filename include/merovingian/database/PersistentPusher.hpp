// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// A push notification pusher registered via `POST
// /_matrix/client/v3/pushers/set` (Matrix v1.19 CS API §push-notifications).
// Keyed by (user_id, app_id, pushkey) — the spec's uniqueness rule: setting a
// pusher with the same app_id and pushkey for the same user replaces it
// in-place rather than creating a second row. `kind` is "http" or "email".
// `data_url` and `data_format` mirror the pusher's `data` dictionary (the
// `url` and `format` keys); `data_url` is required for kind "http" and
// empty for "email". `profile_tag` is optional per spec and empty when unset.
// `data_extra_json` is a canonical-JSON-serialized object holding every
// OTHER member of the pusher's `data` dictionary at registration time (i.e.
// excluding `url`/`format`, which already have dedicated columns above) —
// Matrix v1.19 Push Gateway API requires the homeserver to forward the
// whole `data` dictionary minus `url` to the gateway, not just `format`.
// Empty string means "no extra members" (equivalent to serialized `{}`).
struct PersistentPusher final
{
    std::string user_id{};
    std::string app_id{};
    std::string pushkey{};
    std::string kind{};
    std::string app_display_name{};
    std::string device_display_name{};
    std::string profile_tag{};
    std::string lang{};
    std::string data_url{};
    std::string data_format{};
    std::string data_extra_json{};
    // The device whose access token registered the pusher (`POST /pushers/set`), or empty when
    // none did (a pusher stored before the column existed, or by an appservice). A password
    // change that revokes a device's tokens deletes the pushers that device registered.
    std::string device_id{};
};

} // namespace merovingian::database
