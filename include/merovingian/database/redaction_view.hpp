// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <string_view>

namespace merovingian::database
{

// How redactions are shown to clients (CSAZ-11). Every client-facing event serializer calls both,
// after it has built the client form of an event, so /event, /messages, /context, /sync, sliding
// sync, /relations and /search describe a redacted event the same way.

// Spec (rooms/v11.md, "Moving the `redacts` property"): "servers should add a `redacts` property
// to the top level of `m.room.redaction` events when serving such events over the Client-Server
// API", and to the `content` of such events in older room versions. Does nothing to any other
// event, or to a redaction that carries `redacts` in neither place.
auto add_redaction_compat(canonicaljson::Object& client_event) -> void;

// Spec (Client-Server API, "Redactions"): "Servers should include a copy of the
// `m.room.redaction` event under `unsigned` as `redacted_because` when serving the redacted event
// to clients." Adds it when a redaction has been applied to `event_id`; otherwise does nothing.
auto attach_redacted_because(PersistentStore const& store, std::string_view event_id,
                             canonicaljson::Object& client_event) -> void;

} // namespace merovingian::database
