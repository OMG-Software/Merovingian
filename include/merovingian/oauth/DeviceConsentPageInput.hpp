// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// What the consent page of a device authorisation shows (`device_consent_page`, ADR-0806). Every view is borrowed for
// the call. The client's values are attacker-chosen: each is escaped, and one that cannot be shown is replaced by
// fixed text, never shown raw.
struct DeviceConsentPageInput final
{
    // The pending authorisation identifier, the form's hidden `pending` field.
    std::string_view pending_id{};
    // The user code in its stored form; the page shows it as `XXXX-XXXX`.
    std::string_view user_code{};
    // The registered `client_name`, or none, and the host of its `client_uri` in lower case.
    std::optional<std::string_view> client_name{};
    std::string_view client_host{};
    // The user being signed in, and the device ID the scope names.
    std::string_view user_id{};
    std::string_view device_id{};
    // Whether the user already holds a device with this ID, whose session an approval replaces.
    bool replaces_existing_device{false};
};

} // namespace merovingian::oauth
