// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <string_view>

namespace merovingian::homeserver
{

// CSAZ-11: applying redactions.
//
// Spec (rooms/v3.md to rooms/v12.md, "Handling redactions"): a redaction is applied once both the
// redaction event and the event it affects have been received, if the redaction sender's power
// level is at least the redact level or its domain matches the original event sender's domain. If
// the server applies a redaction, the redaction event is also sent to clients; otherwise the server
// waits for a valid partner event to arrive.
//
// Applying a redaction overwrites the target's stored JSON with its redacted form
// (events::redact_event), in the database and in memory, so the original content is gone from the
// server and cannot be served by any path. The redaction event stays "withheld" from clients
// (database::redaction_is_withheld) until it has been applied.

// Judges and applies every redaction that involves `event_id`: the event itself, if it is a
// redaction, and every stored redaction that names it. Idempotent. Call after storing an event;
// `install_redaction_reconciler` does so for every event stored through the persistent store.
auto reconcile_redactions_for_event(database::PersistentStore& store, std::string_view event_id) -> void;

// Judges and applies every redaction still withheld. Run once at startup, after the store is
// hydrated: it repairs a redaction whose target was never rewritten (a crash between the two
// writes) and re-derives which redactions were applied. Returns how many were applied.
auto reconcile_all_redactions(database::PersistentStore& store) -> std::size_t;

// Makes the persistent store run reconcile_redactions_for_event after every event it stores.
auto install_redaction_reconciler(database::PersistentStore& store) -> void;

enum class LocalRedactionCheck
{
    permitted,
    // The event the redaction names is not in this room, or is not known.
    target_unknown,
    // The sender may not redact it (or it may not be redacted at all).
    forbidden,
};

// Spec (Client-Server API, PUT /redact): "Any user with a power level greater than or equal to the
// `m.room.redaction` event power level may send redactions for their own events in the room. If
// the user's power level is also greater than or equal to the `redact` power level of the room, the
// user may redact events sent by other users. Server administrators may redact events sent by
// users on their server."
//
// `composed_redaction_json` is the signed m.room.redaction event about to be stored. The first
// condition (the power level for `m.room.redaction` itself) is the ordinary event authorization
// the caller has already run; this checks the rest, and that the redaction would then be applied.
[[nodiscard]] auto check_local_redaction(database::PersistentStore const& store, std::string_view room_id,
                                         std::string_view composed_redaction_json, bool sender_is_server_admin,
                                         std::string_view local_server_name) -> LocalRedactionCheck;

} // namespace merovingian::homeserver
