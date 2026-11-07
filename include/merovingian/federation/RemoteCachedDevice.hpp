// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>

namespace merovingian::federation
{

// One device of a remote user, as the remote device-list cache keeps it (ADR-0560). `keys_json` is the device's
// identity keys as canonical JSON, with no `unsigned` member: empty when the device has published none. The display
// name is kept apart and put back under `unsigned.device_display_name` when the device is served to a client.
struct RemoteCachedDevice final
{
    std::string keys_json{};
    std::optional<std::string> display_name{};

    [[nodiscard]] auto operator==(RemoteCachedDevice const&) const -> bool = default;
};

} // namespace merovingian::federation
