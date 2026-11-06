// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// The ephemeral items attached to the transaction currently in flight for one appservice, kept so
// that a retry under the same transaction ID carries exactly the same items ("MUST NOT alter ...
// events they were going to send within that transaction ID on retries"). `events_free` marks a
// transaction that carries no event (ephemeral data alone); its ID comes from the cursor's
// next_txn_id and it is never persisted, so a restart forgets it.
struct AppservicePendingEphemeral final
{
    std::uint64_t txn_id{0U};
    bool events_free{false};
    std::vector<std::string> items{};
};

} // namespace merovingian::homeserver
