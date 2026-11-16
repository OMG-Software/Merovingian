// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/OAuthClientStoreResult.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct PersistentStore;

// The OAuth 2.0 tables of migration 002 (ADR-0776, ADR-0777). Every function here reads or writes
// `PersistentStore::oauth` and, for a write, the database in one transaction, changing memory only after the commit:
// a failed commit changes nothing. None takes a lock; in main the caller holds `runtime.mutex`.

// Caps on what one row holds. A remote client chooses the metadata and the scope, so each is bounded where it is
// stored as well as where it is parsed: an oversized row is refused here, never truncated.
// The canonical client metadata; the registration endpoint's body cap is the same size.
inline constexpr auto max_oauth_client_metadata_bytes = std::size_t{16U} * 1024U;
// A granted scope: the Matrix API scope, one device scope and room for a few more tokens.
inline constexpr auto max_oauth_scope_bytes = std::size_t{2048U};
// A client ID: this server issues them as a keyed hash in text, far shorter than this (plan P2).
inline constexpr auto max_oauth_client_id_bytes = std::size_t{128U};
// `last_used_at_ms` is written only when the stored value is more than this old (ADR-0777): clients register again
// before every login, and a write per registration would make every login cost a commit.
inline constexpr auto oauth_client_touch_interval_ms = std::uint64_t{24U} * 60U * 60U * 1000U;

// Stores a new client. `existing` when its ID is already held, which writes nothing: an existing row's metadata and
// `created_at_ms` never change. `refused` when the ID is empty or longer than `max_oauth_client_id_bytes`, the metadata
// is empty or longer than `max_oauth_client_metadata_bytes`, or the write fails.
[[nodiscard]] auto store_oauth_client(PersistentStore& store, PersistentOAuthClient client) -> OAuthClientStoreResult;
// The client `client_id`, or nullptr. One hash lookup; valid until the next write to the OAuth tables.
[[nodiscard]] auto find_oauth_client(PersistentStore const& store, std::string_view client_id)
    -> PersistentOAuthClient const*;
[[nodiscard]] auto oauth_client_count(PersistentStore const& store) -> std::size_t;
// Records that `client_id` was used at `now_ms`, writing only when its stored `last_used_at_ms` is more than
// `oauth_client_touch_interval_ms` older than `now_ms`. True when the client is held and its row is now fresh enough
// (written or not); false when it is not held or the write failed, leaving the row as it was.
[[nodiscard]] auto touch_oauth_client(PersistentStore& store, std::string_view client_id, std::uint64_t now_ms) -> bool;
// Deletes the clients `client_ids` names, all in one transaction. False, deleting nothing, when an ID is not held,
// is repeated, or names a client with a session (never deleted: spec "Client registration"), or the write fails.
[[nodiscard]] auto delete_oauth_clients(PersistentStore& store, std::span<std::string const> client_ids) -> bool;
// The clients with no session, least recently used first, at most `max`, and only those last used before
// `used_before_ms` (pass UINT64_MAX for all). A client `excluded` answers true for (a pending authorisation or an
// unredeemed code names it) is skipped and does not count against `max`. The walk stops after
// `max_idle_client_rows_examined` clients, whatever it found. Costs the clients walked, not the session table.
[[nodiscard]] auto oauth_clients_without_sessions(PersistentStore const& store, std::size_t max,
                                                  std::uint64_t used_before_ms,
                                                  std::function<bool(std::string_view)> const& excluded = {})
    -> std::vector<std::string>;

// The session of (`user_id`, `device_id`), or nullptr. One hash lookup; valid until the next write.
[[nodiscard]] auto find_oauth_session(PersistentStore const& store, std::string_view user_id,
                                      std::string_view device_id) -> PersistentOAuthSession const*;
// Every session of `user_id`, through the per-user index.
[[nodiscard]] auto oauth_sessions_of_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentOAuthSession>;
[[nodiscard]] auto oauth_client_has_session(PersistentStore const& store, std::string_view client_id) -> bool;

// The `oauth_sessions` INSERT for a transaction that also writes the device and its tokens (phase 6): append it to
// that transaction's statements, commit, and only then call `remember_oauth_session` with the same row. nullopt when
// the row is refused: an empty user, device or client, a client ID or scope over its cap, a client that is not
// held, or a (user, device) that already holds a session. Reads the store; changes nothing.
[[nodiscard]] auto prepare_oauth_session_insert(PersistentStore const& store, PersistentOAuthSession const& session)
    -> std::optional<PreparedStatement>;
// The memory half of `prepare_oauth_session_insert`, after its transaction committed. False when memory already
// holds a session for the device, which cannot happen if nothing wrote between the prepare and the commit.
[[nodiscard]] auto remember_oauth_session(PersistentStore& store, PersistentOAuthSession session) -> bool;
// `prepare_oauth_session_insert`, a transaction of that one statement, then `remember_oauth_session`.
[[nodiscard]] auto store_oauth_session(PersistentStore& store, PersistentOAuthSession session) -> bool;
// Deletes the session of (`user_id`, `device_id`). False when there is none or the write fails. The device stays:
// a device deletion removes its session itself (`delete_device`).
[[nodiscard]] auto delete_oauth_session(PersistentStore& store, std::string_view user_id, std::string_view device_id)
    -> bool;

// The `oauth_sessions` DELETE for one device, which `delete_device` adds to the transaction that deletes the device
// row, so the two never disagree after a commit or a failed one.
[[nodiscard]] auto delete_oauth_session_of_device_statement(std::string_view user_id, std::string_view device_id)
    -> PreparedStatement;

} // namespace merovingian::database
