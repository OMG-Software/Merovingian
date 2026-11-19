// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/StickyEventPush.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/database/StickyEventView.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/federation/OutboundTransactionSupport.hpp"
#include "merovingian/federation/RuntimeFederationConfig.hpp"
#include "merovingian/federation/ServerAcl.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

auto push_local_sticky_events_to_server(HomeserverRuntime& runtime, std::string_view room_id,
                                        std::string_view destination) -> std::size_t
{
    auto const& server_name = runtime.config.server().server_name;
    if (!runtime.config.server().sticky_events.enabled || runtime.dispatch_worker == nullptr || destination.empty() ||
        destination == server_name)
    {
        return 0U;
    }
    auto const& store = runtime.database.persistent_store;
    // ADR-0391: the operator said this server gets nothing. The room's own ACL is judged too: a server the room bans
    // is not sent a room's events, and a join is judged against the ACL when it is accepted, which may have changed.
    if (!federation::federation_server_policy(runtime.federation.config, destination).allowed ||
        !federation::room_server_acl_allows(store, room_id, destination))
    {
        return 0U;
    }
    auto const rows = store.sticky_events.unexpired_of_room(room_id, database::sticky_clock_now_ms(store));
    auto batch = std::vector<federation::OutboundTransaction>{};
    for (auto const* const row : rows)
    {
        // Our own senders only, whatever the table holds: a remote server's sticky event is never relayed.
        if (auth::user_id_server_name(row->sender) != server_name)
        {
            continue;
        }
        auto const stored = store.events.find(row->event_id);
        if (stored == store.events.end() || stored->room_id != room_id)
        {
            continue;
        }
        auto const body = federation::build_pdu_transaction_body(server_name, stored->json);
        if (!body.has_value())
        {
            observability::log_diagnostic(
                "rooms", "sticky_event.push_refused",
                {
                    {"room_id",  std::string{room_id}, false},
                    {"event_id", row->event_id,        false}
            },
                observability::LogEventSeverity::error);
            continue;
        }
        // One transaction ID per transaction: it is the durable queue row's key.
        auto const tx_id = federation::make_federation_transaction_id();
        auto target = "/_matrix/federation/v1/send/" + tx_id;
        auto transaction =
            federation::make_outbound_transaction(std::string{destination}, "PUT", target, server_name, *body);
        transaction.transaction_id = tx_id;
        batch.push_back(std::move(transaction));
    }
    if (batch.empty())
    {
        return 0U;
    }
    auto const accepted = runtime.dispatch_worker->enqueue_batch(std::move(batch));
    auto const count = static_cast<std::size_t>(std::ranges::count(accepted, true));
    if (count != accepted.size())
    {
        // Not retried: the queue is in memory and bounded (ADR-0856, known gaps).
        observability::log_diagnostic("rooms", "sticky_event.push_refused",
                                      {
                                          {"room_id",     std::string{room_id},                    false},
                                          {"destination", std::string{destination},                false},
                                          {"refused",     std::to_string(accepted.size() - count), false}
        },
                                      observability::LogEventSeverity::warning);
    }
    return count;
}

} // namespace merovingian::homeserver
