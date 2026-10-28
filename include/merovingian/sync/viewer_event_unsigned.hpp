// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/history_visibility.hpp"

#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::sync
{

// The parts of a ClientEvent's `unsigned` that depend on who is asking (client-server-api.md,
// ClientEvent `unsigned`):
//
//   - `transaction_id`: "The client-supplied transaction ID ... if the client being given the
//     event is the same one which sent it." A transaction ID is scoped to a device ("Transaction
//     identifiers"), so the device that sent the event with a transaction ID is given it, whatever
//     access token it now holds. No other device, and no other user, is.
//   - `membership`: "The room membership of the user making the request, at the time of the
//     event", `leave` for a user with no membership yet.
//
// One instance serves one request: it reads the requesting device's transaction IDs from the
// store once, on first use, and answers memberships through the request's HistoryVisibility.
// It is not thread-safe and must not outlive the store or the visibility it was built with.
class ViewerEventUnsigned final
{
public:
    ViewerEventUnsigned(database::PersistentStore const& store, HistoryVisibility& visibility, std::string_view user_id,
                        std::string_view device_id);

    // `client_event` (the serialisation of `event`) with the viewer's `unsigned.transaction_id`
    // and `unsigned.membership` added, replacing any the stored event carried.
    [[nodiscard]] auto apply(database::PersistentEvent const& event, canonicaljson::Value client_event)
        -> canonicaljson::Value;

private:
    auto ensure_transactions() -> void;

    database::PersistentStore const& store_;
    HistoryVisibility& visibility_;
    std::string user_id_;
    std::string device_id_;
    bool transactions_built_{false};
    // event_id -> transaction ID, for the events this user's device sent with one.
    std::unordered_map<std::string, std::string> transactions_{};
};

} // namespace merovingian::sync
