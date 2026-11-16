// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// One device as the account pages show it. Every view is borrowed for the call. The display name and the client name
// are chosen by a client: the page builder escapes them and shows fixed text for one it cannot show.
struct AccountDeviceRow final
{
    // A device ID that passed `auth::device_id_is_valid`.
    std::string_view device_id{};
    // The device's display name, empty when none was set.
    std::string_view display_name{};
    // Whether the device signed in through the OAuth 2.0 API (it has an `oauth_sessions` row).
    bool oauth_session{false};
    // For an OAuth device, the registered `client_name` of its client, or nullopt when the client registered none or
    // is no longer registered.
    std::optional<std::string_view> client_name{};
};

} // namespace merovingian::oauth
