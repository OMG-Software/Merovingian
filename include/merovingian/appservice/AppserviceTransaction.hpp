// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceTransactionEvent.hpp"

#include <string>
#include <vector>

namespace merovingian::appservice
{

// One `PUT /_matrix/app/v1/transactions/{txnId}` call's worth of events.
// `ephemeral_json` is the request body's `ephemeral` array (m.presence,
// m.typing and m.receipt, spec v1.13): each element is one already-serialized
// event object, built by homeserver/appservice_ephemeral.hpp, and is parsed
// back only to be embedded. The property is omitted when the list is empty.
struct AppserviceTransaction final
{
    std::string txn_id{};
    std::vector<AppserviceTransactionEvent> events{};
    std::vector<std::string> ephemeral_json{};
};

} // namespace merovingian::appservice
