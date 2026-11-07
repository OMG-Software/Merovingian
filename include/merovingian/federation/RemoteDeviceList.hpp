// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/RemoteCachedDevice.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>

namespace merovingian::federation
{

// A remote user's whole device list at one position of their server's device-list stream: the answer to
// `GET /_matrix/federation/v1/user/devices/{userId}`, kept up to date by `m.device_list_update` EDUs (ADR-0560).
// The cross-signing keys are canonical JSON, each already checked to be that user's key for its usage.
struct RemoteDeviceList final
{
    std::int64_t stream_id{0};
    std::map<std::string, RemoteCachedDevice, std::less<>> devices{};
    std::optional<std::string> master_key_json{};
    std::optional<std::string> self_signing_key_json{};

    // What the list costs to hold, in bytes of its strings: what the cache's byte caps count.
    [[nodiscard]] auto bytes() const noexcept -> std::size_t;
};

} // namespace merovingian::federation
