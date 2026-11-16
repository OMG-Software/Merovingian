// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// The most idle clients one `OAuthTables::idle_clients` call examines (ADR-0782). The walk runs under `runtime.mutex`
// and skips every client a pending authorisation or an unredeemed code names, so without a bound its cost was bounded
// only by the client cap. 16 896 is the 8192 pending authorisations plus the 8192 codes the homeserver can hold (each
// names one client, so at most 16 384 clients are skipped) plus 512, more than any caller asks for
// (`retention_batch_rows` 500; `RetentionSweep.cpp` and `OAuthClientRegistration.cpp` assert it): a walk that stops
// here has therefore already found `max` clients or every idle one. A walk that finds nothing within it answers
// "nothing can go".
inline constexpr auto max_idle_client_rows_examined = std::size_t{16'896U};

// The in-memory copy of `oauth_clients` and `oauth_sessions` (migration 002, ADR-0776, ADR-0777). The class owns the
// rows and shows them read-only, so a writer that bypasses it does not compile and its indexes cannot drift from the
// rows. A client is found by ID and a session by (user, device) with one hash lookup; a user's sessions through a
// per-user index; and the clients that hold no session are kept in an ordered set by `last_used_at_ms`, so "the
// least recently used clients without a session" never walks the session table. The table has no lock: a reader
// needs exclusion from writers (in main, `runtime.mutex`). A pointer it returns is valid until the next write. The
// defaulted copy and move keep every index valid: the indexes hold keys, never positions or pointers.
class OAuthTables final
{
public:
    // The row for `client_id`, or nullptr.
    [[nodiscard]] auto find_client(std::string_view client_id) const -> PersistentOAuthClient const*;
    [[nodiscard]] auto client_count() const noexcept -> std::size_t
    {
        return clients_.size();
    }
    // How many sessions name `client_id`, whether or not the client row is held.
    [[nodiscard]] auto sessions_of_client(std::string_view client_id) const -> std::size_t;

    // Adds `client`. False, and nothing changes, when its ID is already held.
    auto insert_client(PersistentOAuthClient client) -> bool;
    // Sets a held client's `last_used_at_ms`. False when `client_id` is not held.
    auto set_client_last_used(std::string_view client_id, std::uint64_t last_used_at_ms) -> bool;
    // Removes a client. False, and nothing changes, when it is not held or a session names it: a client with a
    // session is never deleted (spec, "Client registration": the server "MUST NOT delete client registrations that have
    // an active session").
    auto erase_client(std::string_view client_id) -> bool;

    // The held clients no session names, least recently used first (ties by ID), stopping at `max` IDs, at the
    // first client used at or after `used_before_ms`, or once `max_idle_client_rows_examined` clients were examined.
    // A client `excluded` answers true for is skipped. Costs the clients walked, counted in `rows_examined`, never the
    // session table.
    [[nodiscard]] auto idle_clients(std::size_t max, std::uint64_t used_before_ms,
                                    std::function<bool(std::string_view)> const& excluded) const
        -> std::vector<std::string>;

    // The session of (`user_id`, `device_id`), or nullptr.
    [[nodiscard]] auto find_session(std::string_view user_id, std::string_view device_id) const
        -> PersistentOAuthSession const*;
    [[nodiscard]] auto session_count() const noexcept -> std::size_t
    {
        return sessions_.size();
    }
    // Every session of `user_id`, in no particular order. Costs the user's own sessions, counted in
    // `rows_examined`.
    [[nodiscard]] auto sessions_of_user(std::string_view user_id) const -> std::vector<PersistentOAuthSession>;

    // Adds `session`. False, and nothing changes, when (user, device) already holds one. The client need not be
    // held (hydration may load the sessions first); a held client named by it stops being idle.
    auto insert_session(PersistentOAuthSession session) -> bool;
    // Removes the session of (`user_id`, `device_id`). False when there is none.
    auto erase_session(std::string_view user_id, std::string_view device_id) -> bool;

    auto clear() noexcept -> void;

    // Rows every reader above looked at over the table's life, for tests that prove cost.
    [[nodiscard]] auto rows_examined() const noexcept -> std::uint64_t
    {
        return rows_examined_.value();
    }

private:
    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, detail::StateGroupKeyHash, std::equal_to<>>;

    // A client is idle while no session names it; `idle_` then holds (last_used_at_ms, client_id).
    auto mark_idle(PersistentOAuthClient const& client) -> void;
    auto unmark_idle(PersistentOAuthClient const& client) -> void;

    KeyedBy<PersistentOAuthClient> clients_{};
    // (user_id NUL device_id) -> the session.
    KeyedBy<PersistentOAuthSession> sessions_{};
    // user_id -> that user's device IDs that hold a session.
    KeyedBy<std::set<std::string, std::less<>>> devices_by_user_{};
    // client_id -> how many sessions name it; absent means none.
    KeyedBy<std::size_t> sessions_by_client_{};
    std::set<std::pair<std::uint64_t, std::string>> idle_{};
    ExaminedRows rows_examined_{};
};

} // namespace merovingian::database
