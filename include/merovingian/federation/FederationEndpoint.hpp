// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::federation
{

enum class FederationEndpoint
{
    transaction,
    make_join,
    send_join,
    make_leave,
    send_leave,
    make_knock,
    send_knock,
    invite,
    backfill,
    edu,
    query_directory,
    public_rooms,
    query_profile,
    query_keys,
    claim_keys,
    query_user_devices,
    query_event,
    query_state,
    query_state_ids,
    event_auth,
    get_missing_events,
    space_hierarchy,
    timestamp_to_event,
    media_download,
    media_thumbnail,
    exchange_third_party_invite,
};

} // namespace merovingian::federation
