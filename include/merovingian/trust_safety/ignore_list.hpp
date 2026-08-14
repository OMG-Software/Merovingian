// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::trust_safety
{

// Matrix v1.19 CS API "Ignoring Users" module.
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users
//
// The account-data event `m.ignored_user_list` (global, room_id empty) holds
// `{"ignored_users": {"<user id>": {}, ...}}` — a set of user IDs the account
// owner wants the server to stop delivering events from. This module is the
// single place that parses that list and decides whether a given delivery
// (a timeline event, an ephemeral typing/receipt entry, a room invite, or a
// push notification) should be withheld. Every enforcement call site —
// /sync, MSC4186 sliding sync, /messages, /context, and push delivery —
// calls into these functions rather than re-implementing the predicate.

// Parses the content of an `m.ignored_user_list` account-data event into the
// set of ignored user IDs. Fails safe: missing content, a missing/wrong-typed
// `ignored_users` member, or malformed JSON all parse to an empty set
// ("nothing ignored") rather than throwing or propagating a parse error —
// callers must never treat a broken ignore list as blocking legitimate
// delivery. Non-string / non-object member shapes inside `ignored_users` are
// individually skipped rather than failing the whole parse, mirroring
// push::parse_push_ruleset's "one corrupt row cannot take down the rest"
// policy.
[[nodiscard]] auto parse_ignored_user_list(std::string_view content_json) -> std::unordered_set<std::string>;

// Resolves `user_id`'s current ignore set by reading their global (room_id
// empty) `m.ignored_user_list` account-data row from `store`, if any. Returns
// an empty set when no such row exists. Pure/in-memory: no I/O beyond the
// already-loaded `store.account_data` vector.
//
// Callers MUST resolve this ONCE per request (or once per recipient per
// delivery batch, e.g. once per push-notification fan-out) and reuse the
// result — never re-resolve inside a per-event loop.
[[nodiscard]] auto resolve_ignored_users(database::PersistentStore const& store, std::string_view user_id)
    -> std::unordered_set<std::string>;

// Pure decision: should a delivery whose sender is `sender` be withheld from
// a recipient whose resolved ignore set is `ignored_senders`?
//
// Per spec, Server behaviour:
//   - "Servers must still send state events sent by ignored users to
//     clients." -> when `is_state_event` is true, this always returns false
//     (never suppressed), regardless of ignore status.
//   - "Servers must not send room invites from ignored users to clients."
//     -> `is_new_room_invite` overrides the state-event exemption above: an
//     invite extended by an ignored sender is suppressed even though the
//     underlying m.room.member event has a state_key.
//   - Everything else from an ignored sender (messages and other non-state
//     events) is suppressed.
//
// Fails safe: an empty `ignored_senders` set (absent or malformed ignore
// list) means `contains` is always false, so this returns false — nothing is
// ever suppressed by a broken or missing ignore list.
[[nodiscard]] auto is_delivery_suppressed(std::unordered_set<std::string> const& ignored_senders,
                                          std::string_view sender, bool is_state_event,
                                          bool is_new_room_invite = false) noexcept -> bool;

// Discriminator shared with room_service.hpp's client_event_with_id /
// ingest_send_join_state: an event is a state event iff its raw JSON has a
// "state_key" member, regardless of that member's value (including ""). This
// re-parses `event_json`; callers that already hold a parsed
// canonicaljson::Object should check for "state_key" directly instead of
// calling this. Fails safe: malformed JSON is treated as "not a state event"
// (never exempted from suppression by a parse failure).
[[nodiscard]] auto event_json_is_state_event(std::string_view event_json) -> bool;

} // namespace merovingian::trust_safety
