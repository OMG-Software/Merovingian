// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncLimits.hpp"

#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

struct ClientApiLimits final
{
    // The body limit is snapshotted from server.client_api.max_body_size at startup.
    std::size_t max_body_bytes{1024U * 1024U};
    std::uint32_t max_sync_rooms{1000U};
    std::uint32_t max_sync_events_per_room{100U};
    // POST /search has no per-room scope (unlike /messages) and no secondary
    // full-text index (see docs/architecture.md's "Server-side search"
    // section): it walks the joined-room subset of PersistentStore::events
    // directly. This bounds the number of candidate events a single request
    // will JSON-parse and text-match before it must stop and hand back a
    // `next_batch` continuation, so one cheap authenticated request cannot
    // force an O(store size) scan.
    std::uint32_t max_search_events_scanned{10000U};
    // GET /messages hides events the user may not see (m.room.history_visibility), and
    // any number of consecutive events can be hidden. This bounds how many events one page
    // examines before it returns what it has, with an `end` token to continue from; the spec
    // allows it ("an empty chunk does not necessarily imply that no more events are available").
    std::uint32_t max_messages_events_examined{10000U};
    std::uint32_t max_messages_page_size{500U};
    std::uint32_t max_context_events{100U};
    std::uint32_t max_search_page_size{100U};
    std::uint32_t max_search_context_events{100U};
    std::uint32_t max_registration_validation_sessions{1024U};
    std::uint32_t max_registration_validation_sessions_per_remote{16U};
    std::uint32_t max_uia_sessions{2048U};
    // CS8 (ADR-0548): login tokens minted by POST /login/get_token and not yet redeemed. A token lives
    // `login_token_lifetime_ms` (the spec's recommended two minutes); a user holds at most
    // `max_login_tokens_per_user` and the server `max_login_tokens`. Over either, get_token answers 429.
    std::uint32_t max_login_tokens{1024U};
    std::uint32_t max_login_tokens_per_user{4U};
    std::uint32_t login_token_lifetime_ms{120000U};
    std::uint32_t max_safety_report_rows{1000U};
    std::uint32_t max_notifications_page_size{1000U};
    std::uint32_t max_relations_page_size{500U};
    std::uint32_t max_public_rooms_page_size{1000U};
    std::uint32_t max_hierarchy_rooms{1000U};
    // CSAZ-10: per-user caps on stored end-to-end key material and filters.
    // An upload over a cap is refused with M_TOO_LARGE; nothing is evicted.
    std::uint32_t max_one_time_keys_per_device{1000U};
    std::uint32_t max_key_signatures_per_user{10000U};
    std::uint32_t max_filters_per_user{1000U};
    // Security audit run-1 (ADR-0173): global account-data types per user.
    std::uint32_t max_global_account_data_per_user{1000U};
    // Conformance audit R10 (ADR-0197): client-set account-data types per user per room.
    std::uint32_t max_room_account_data_per_room{100U};
    // User-defined push rules per user across all five kinds; over -> M_TOO_LARGE.
    std::uint32_t max_push_rules_per_user{200U};
    // Security audit run-2 (ADR-0316): entries of one POST /createRoom; over -> M_TOO_LARGE.
    std::uint32_t max_create_room_invites{100U};
    std::uint32_t max_create_room_initial_state{100U};
    // Security audit run-2 F-13 (ADR-0336): local deliveries (a "*" counts one per device) of one
    // PUT /sendToDevice; over -> 413 M_TOO_LARGE, nothing queued. Inbound EDUs have their own cap.
    std::uint32_t max_send_to_device_deliveries{1000U};
    sync::SlidingSyncLimits sliding_sync{500U, 1024U, 1024U};
    std::uint32_t sliding_sync_connections_per_device{16U};
};

} // namespace merovingian::homeserver
