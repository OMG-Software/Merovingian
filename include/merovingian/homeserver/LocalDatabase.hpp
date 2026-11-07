// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/LocalUser.hpp"
#include "merovingian/homeserver/RoomPositionIndex.hpp"
#include "merovingian/homeserver/session_table.hpp"
#include "merovingian/observability/AuditLogEvent.hpp"
#include "merovingian/observability/audit_rate_gate.hpp"

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct LocalDatabase final
{
    bool opened{false};
    bool schema_validated{false};
    std::uint32_t schema_version{0U};
    std::uint64_t next_session_id{1U};
    std::uint64_t next_event_id{1U};
    std::vector<std::string> tables{};
    std::vector<LocalUser> users{};
    SessionTable sessions{};
    std::vector<LocalRoom> rooms{};
    // Position in `rooms` of each room ID (ADR-0496, ADR-0521). A verified cache with its own mutex: a lookup through
    // it is correct however `rooms` was edited, and a copy or move of the database starts with it empty.
    RoomPositionIndex room_positions{};
    // Bounded window over the most recent `database::max_in_memory_audit_events`
    // audit events (AUTH-1); the oldest is dropped first. The durable copy of
    // every event is the audit_log table, reachable through `persistent_store`.
    std::list<observability::AuditLogEvent> audit_events{};
    // Rate-caps the audit events an unauthenticated client can trigger on every
    // request (AUTH-1, ADR-0080). Guarded by the runtime mutex like the audit rows.
    observability::AuditRateGate audit_rate_gate{};
    database::PersistentStore persistent_store{};
    // True in a federation worker (the `federation_worker` load profile), whose
    // in-memory `server_signing_keys` is a snapshot taken at start-up: its remote
    // key resolver then re-reads a server's public key rows from the database
    // before it fetches (`federation::KeyMirrorRefresh::on_miss`). Main keeps
    // the authoritative mirror and leaves it false.
    bool remote_signing_keys_read_through{false};
    core::SecretBuffer signing_secret_key{};
    // All currently-active server signing secrets loaded into the runtime, keyed
    // by key_id. Used to build the multi-key Ed25519 provider so events and
    // federation responses can be signed with any active key.
    std::vector<std::pair<std::string, core::SecretBuffer>> signing_secret_keys{};
    // Keyed secret used to sign opaque pagination tokens issued by endpoints such
    // as GET /_matrix/client/v1/mutual_rooms. Derived once at runtime start from
    // the server signing key so tokens are server-scoped and survive restarts.
    std::optional<core::SecretBuffer> mutual_rooms_token_key{};
    // Cache of the signed /_matrix/key/v2/server response, protected by its own
    // internal mutex so the federation key endpoint can be served without acquiring
    // the global runtime mutex. Wrapped in unique_ptr so LocalDatabase remains
    // move-constructible (std::mutex is not moveable).
    std::unique_ptr<KeyServerCache> key_server_cache{std::make_unique<KeyServerCache>()};
    std::uint64_t next_stream_ordering{1U};
    // ADR-0247: orderings reserved for events that are committed with
    // runtime.mutex released and not yet applied to the store. No sync
    // position passes the oldest of them (visible_stream_position). Guarded by
    // runtime.mutex; entries are added and removed only by PendingStreamOrdering.
    std::multiset<std::uint64_t> pending_stream_orderings{};
};

static_assert(std::is_nothrow_move_constructible_v<LocalDatabase> && std::is_nothrow_move_assignable_v<LocalDatabase>);

} // namespace merovingian::homeserver
