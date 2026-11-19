// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtAccountDataResponse.hpp"
#include "merovingian/sync/ExtE2eeResponse.hpp"
#include "merovingian/sync/ExtReceiptsResponse.hpp"
#include "merovingian/sync/ExtToDeviceResponse.hpp"
#include "merovingian/sync/ExtTypingResponse.hpp"
#include "merovingian/sync/ExtensionScopeHistory.hpp"

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
    // What this response leaves in the typing and receipts scope, for the connection to keep with the response
    // (ADR-0863). Set only when the caller passed `ExtensionScopeSource::history`.
    std::optional<ExtensionScopeHistory> scope_history{};
    // This response sent a room entering the typing scope its typing state, or a room re-entering the receipts scope
    // receipts from before the request's position. Neither moves a stream, so the handler gives such a response a
    // `pos` page (ADR-0862) and the next request acknowledges it rather than reading as a retry.
    bool sent_on_scope_entry{false};
};

} // namespace merovingian::sync
