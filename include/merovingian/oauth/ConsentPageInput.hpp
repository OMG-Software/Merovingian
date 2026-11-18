// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// What the consent page of an authorisation shows (`consent_page`), beside the redirect target it is given. Every view
// is borrowed for the call. The client's values are attacker-chosen: each is escaped, and one that cannot be shown is
// replaced by fixed text, never shown raw.
struct ConsentPageInput final
{
    // The pending authorisation identifier, the form's hidden `pending` field.
    std::string_view pending_id{};
    // The registered `client_name`, or none.
    std::optional<std::string_view> client_name{};
    // The host of the registered `client_uri`, in lower case.
    std::string_view client_host{};
    // The user being signed in, and the device ID the scope names.
    std::string_view user_id{};
    std::string_view device_id{};
    // The registered `policy_uri` and `tos_uri`, linked when present.
    std::optional<std::string_view> policy_uri{};
    std::optional<std::string_view> tos_uri{};
    // Whether the user already holds a device with this ID, whose session an approval replaces (spec "Scope").
    bool replaces_existing_device{false};
};

} // namespace merovingian::oauth
