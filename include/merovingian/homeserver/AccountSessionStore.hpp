// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/homeserver/AccountSession.hpp"
#include "merovingian/homeserver/HashedSecretTable.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

// The signed-in sessions of the account pages at `/_merovingian/account` (plan P6, ADR-0796). In memory only: a session
// lives 15 minutes from sign-in and is never extended, and a restart signs every browser out of the pages and nothing
// else.
//
// A session is held under the hash of a fresh 256-bit secret (`make_oauth_secret`), which `create` returns once for the
// `__Host-mv-account` cookie; the secret itself is never kept. Every form of a signed-in page also carries the
// session's form token (`form_token`): a hash of the secret under its own label, so it is bound to the session, is not
// the cookie value, and cannot be derived from what the store keeps.
//
// Bounded: `max_sessions` in all and `max_sessions_per_user` per user. A sign-in first purges the expired sessions; a
// user at the per-user cap then loses their own oldest session (never another user's), and at the total cap the
// sign-in is refused. Expired sessions are removed at the start of every operation, soonest first, at the cost of the
// sessions removed. An expired session behaves as absent.
//
// Every operation takes the current time, so a test needs no clock. Not thread-safe: `runtime.mutex` serialises every
// use (the store is `HomeserverRuntime::account_sessions`).
class AccountSessionStore final
{
public:
    // A session lives this long from sign-in and is never extended: long enough to delete a device or change a
    // password, short enough that a browser left open is not a standing credential (plan P6).
    static constexpr auto lifetime_ms = std::uint64_t{900'000U};
    // At most this many sessions in all: a session is about a hundred bytes, so the store stays well under a MiB, and
    // each one needed a verified password, which the login throttle and the Argon2id budget already limit.
    static constexpr auto max_sessions = std::size_t{4096U};
    // At most this many per user: a person has a browser or two open on these pages at once; a fifth sign-in replaces
    // that user's oldest, so a user cannot fill the store and nobody can end another user's session by signing in.
    static constexpr auto max_sessions_per_user = std::size_t{4U};

    enum class Refusal : std::uint8_t
    {
        // `max_sessions` live sessions are held, none of them the user's.
        store_full,
        // The user ID is empty.
        no_user,
        // The random source or the hash failed.
        secret_unavailable,
    };

    // A fresh session for `user_id`, valid for `lifetime_ms` from `now_ms`. Returns its secret (64 hex digits), once,
    // or why nothing was stored. Never reuses a secret a request supplied.
    [[nodiscard]] auto create(std::string_view user_id, std::uint64_t now_ms) -> std::variant<std::string, Refusal>;

    // A copy of the live session `secret` names, or nullopt. Compared in constant time through the digest index.
    [[nodiscard]] auto find(std::string_view secret, std::uint64_t now_ms) -> std::optional<AccountSession>;

    // Ends the session `secret` names. False when there is none.
    auto end(std::string_view secret, std::uint64_t now_ms) -> bool;

    // Ends every session of `user_id` (sign-out of a deactivated account, a password change). Returns how many ended.
    // Costs the user's own sessions, at most `max_sessions_per_user`.
    auto end_user(std::string_view user_id) -> std::size_t;

    // The form token of the session `secret` names: BLAKE2b-256 of a fixed label and the secret, as hex. nullopt when
    // hashing fails or the secret is empty.
    [[nodiscard]] static auto form_token(std::string_view secret) -> std::optional<std::string>;

    // Whether `offered` is the form token of `secret`, compared in constant time.
    [[nodiscard]] static auto form_token_matches(std::string_view secret, std::string_view offered) -> bool;

    // How many live sessions `user_id` holds, after removing the expired ones.
    [[nodiscard]] auto live_count_for_user(std::string_view user_id, std::uint64_t now_ms) -> std::size_t;

    // Removes every session whose lifetime ended at or before `now_ms`.
    auto erase_expired(std::uint64_t now_ms) -> void;

    // Sessions held, expired ones not yet removed included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        AccountSession session{};
        // The key the table holds the entry under, kept here too so the per-user index can be updated when the
        // table hands an expired entry back.
        std::string secret_hash{};
    };

    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, database::detail::StateGroupKeyHash, std::equal_to<>>;

    // Drops an entry that left the table from the per-user index.
    auto forget(Entry const& entry) -> void;
    // Removes the session held under `secret_hash` from the table and the index.
    auto erase_hash(std::string_view secret_hash) -> bool;

    HashedSecretTable<Entry> m_sessions{};
    // user_id -> the hashes of the user's sessions, oldest first. At most `max_sessions_per_user` each.
    KeyedBy<std::vector<std::string>> m_hashes_by_user{};
};

} // namespace merovingian::homeserver
