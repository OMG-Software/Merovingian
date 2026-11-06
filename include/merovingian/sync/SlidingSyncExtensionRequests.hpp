// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtAccountDataRequest.hpp"
#include "merovingian/sync/ExtE2eeRequest.hpp"
#include "merovingian/sync/ExtReceiptsRequest.hpp"
#include "merovingian/sync/ExtToDeviceRequest.hpp"
#include "merovingian/sync/ExtTypingRequest.hpp"

#include <optional>

namespace merovingian::sync
{

struct SlidingSyncExtensionRequests final
{
    std::optional<ExtToDeviceRequest> to_device{};
    std::optional<ExtE2eeRequest> e2ee{};
    std::optional<ExtAccountDataRequest> account_data{};
    std::optional<ExtReceiptsRequest> receipts{};
    std::optional<ExtTypingRequest> typing{};
};

} // namespace merovingian::sync
