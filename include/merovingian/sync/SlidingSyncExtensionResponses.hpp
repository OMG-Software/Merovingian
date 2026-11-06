// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtAccountDataResponse.hpp"
#include "merovingian/sync/ExtE2eeResponse.hpp"
#include "merovingian/sync/ExtReceiptsResponse.hpp"
#include "merovingian/sync/ExtToDeviceResponse.hpp"
#include "merovingian/sync/ExtTypingResponse.hpp"

#include <optional>

namespace merovingian::sync
{

struct SlidingSyncExtensionResponses final
{
    std::optional<ExtToDeviceResponse> to_device{};
    std::optional<ExtE2eeResponse> e2ee{};
    std::optional<ExtAccountDataResponse> account_data{};
    std::optional<ExtReceiptsResponse> receipts{};
    std::optional<ExtTypingResponse> typing{};
};

} // namespace merovingian::sync
