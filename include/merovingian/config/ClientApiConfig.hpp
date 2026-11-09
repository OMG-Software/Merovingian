// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// Deployment work budgets, not protocol maxima. Startup snapshots these
// settings; every key in server.client_api requires a restart.
struct ClientApiConfig final
{
    std::string max_body_size{"1MiB"};
    std::uint32_t max_sync_rooms{1000U};
    std::uint32_t max_sync_events_per_room{100U};
    std::uint32_t max_search_events_scanned{10000U};
    std::uint32_t max_messages_events_examined{10000U};
    std::uint32_t max_messages_page_size{500U};
    std::uint32_t max_context_events{100U};
    std::uint32_t max_search_page_size{100U};
    std::uint32_t max_search_context_events{100U};
    std::uint32_t sliding_sync_max_timeline_limit{100U};
    std::uint32_t sliding_sync_max_room_subscriptions{256U};
    std::uint32_t sliding_sync_max_required_state_entries{256U};
    std::uint32_t sliding_sync_connections_per_device{16U};
    std::uint32_t max_registration_validation_sessions{1024U};
    std::uint32_t max_registration_validation_sessions_per_remote{16U};
    std::uint32_t max_uia_sessions{2048U};
    std::uint32_t max_safety_report_rows{1000U};
    std::uint32_t max_notifications_page_size{1000U};
    std::uint32_t max_notifications_retained_per_user{1000U};
    std::uint32_t max_relations_page_size{500U};
    std::uint32_t max_threads_page_size{500U};
    // CSAZ-10: bound the per-recipient to-device queue so undelivered rows
    // (for example to a non-existent device) cannot grow without limit.  The
    // cap is per (user, device); the TTL drops any row older than the limit
    // regardless of acknowledgement.  Both are enforced at enqueue and drain
    // time, so the queue stays bounded even for recipients that never sync.
    std::uint32_t max_to_device_messages_per_user_device{10000U};
    std::uint32_t to_device_message_ttl_seconds{604800U};
    // Security audit run-2 F-14 (ADR-0335): the queue is bounded in bytes as well. A to-device
    // message whose content is over max_to_device_message_bytes is refused (413 M_TOO_LARGE for a
    // client; one message of an inbound m.direct_to_device EDU is dropped, the rest are kept). A
    // recipient (user, device) whose queued bytes would pass max_to_device_bytes_per_user_device
    // loses its oldest rows to make room, as the row-count cap does.
    std::uint32_t max_to_device_message_bytes{65536U};
    std::uint32_t max_to_device_bytes_per_user_device{16777216U};
    // CSAZ-10: bound the end-to-end key material and filters one user can
    // store.  An upload that would take the user over a cap is refused with
    // M_TOO_LARGE and stores nothing; stored rows are never evicted to make
    // room.  Re-uploading an id the user already holds does not count twice.
    //   - max_one_time_keys_per_device: one-time keys held per (user, device).
    //   - max_key_signatures_per_user: cross-signing signatures a user has
    //     uploaded, counted per (target user, target key).
    //   - max_filters_per_user: stored sync filters per user.
    //   - max_global_account_data_per_user: global (non-room) account-data
    //     types per user; updating a type the user holds is always allowed.
    //     Room account data is not counted here. ADR-0173.
    //   - max_room_account_data_per_room: client-set account-data types a
    //     user holds in one room, written only for a room the user holds a
    //     membership in; updating a held type is always allowed. The m.tag
    //     and m.fully_read rows the tags and read-marker APIs write count
    //     towards it but are never refused. ADR-0197.
    //   - max_push_rules_per_user: user-defined push rules (created through
    //     PUT /pushrules/global/{kind}/{ruleId}, across all five kinds) per
    //     user; server-default rules are not counted and updating an existing
    //     rule is always allowed.
    std::uint32_t max_one_time_keys_per_device{1000U};
    std::uint32_t max_key_signatures_per_user{10000U};
    std::uint32_t max_filters_per_user{1000U};
    std::uint32_t max_global_account_data_per_user{1000U};
    std::uint32_t max_room_account_data_per_room{100U};
    std::uint32_t max_push_rules_per_user{200U};
    // Security audit run-4 F-03 (ADR-0581): room aliases one user may have created through
    // PUT /directory/room and createRoom's `room_alias_name` (an application service is exempt),
    // and aliases one room may hold (nobody is exempt). A new alias past either is refused with
    // M_TOO_LARGE; an alias that exists keeps its old answer.
    std::uint32_t max_room_aliases_per_user{100U};
    std::uint32_t max_room_aliases_per_room{100U};
    std::uint32_t max_public_rooms_page_size{1000U};
    std::uint32_t max_hierarchy_rooms{1000U};
    // Security audit run-2 (ADR-0316): entries of one POST /createRoom. Each stores one
    // event under the runtime lock; a request past either is refused before anything is stored.
    std::uint32_t max_create_room_invites{100U};
    std::uint32_t max_create_room_initial_state{100U};
};

} // namespace merovingian::config
