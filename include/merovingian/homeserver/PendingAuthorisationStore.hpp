// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/homeserver/HashedSecretTable.hpp"
#include "merovingian/homeserver/PendingAuthorisation.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace merovingian::homeserver
{

// The authorisation requests waiting for their user (plan P5, ADR-0782). In memory only: an entry lives ten minutes,
// and a restart ends a login in progress and nothing else.
//
// An entry is held under the hash of a fresh 256-bit identifier, which `create` returns once (the page carries it in a
// hidden form field); the identifier itself is never kept. It is bound to the browser by the hash of the
// browser-binding token, the value of a cookie: every operation that names an entry needs both, the token is compared
// in constant time, and a wrong token is answered exactly as an unknown identifier is.
//
// Bounded: `max_entries` in all and `max_entries_per_address` per client address key. At a cap the expired entries
// are purged and, if it is still full, the creation is refused. A live entry is never evicted: a flood of requests
// must not be able to end another user's login in progress. Expired entries are removed at the start of every
// operation, soonest first, at the cost of the entries removed. An expired entry behaves as absent.
//
// Every operation takes the current time, so a test needs no clock. Not thread-safe: `runtime.mutex` serialises every
// use (the store is `HomeserverRuntime::oauth_pending_authorisations`).
class PendingAuthorisationStore final
{
public:
    // An entry lives this long from its creation; authenticating does not extend it (spec leaves the lifetime to the
    // server; ten minutes is long enough to type a password and register, short enough not to be a standing grant).
    static constexpr auto lifetime_ms = std::uint64_t{600'000U};
    // At most this many entries in all: an entry is a few hundred bytes, so the store stays under a few MiB, and the
    // retention sweep's walk past clients with pending entries stays bounded (ADR-0782).
    static constexpr auto max_entries = std::size_t{8192U};
    // At most this many entries per client address key: one browser has a handful of logins in flight at most, and an
    // address cannot fill the store alone.
    static constexpr auto max_entries_per_address = std::size_t{16U};

    enum class Refusal : std::uint8_t
    {
        // `max_entries` live entries are held.
        store_full,
        // `max_entries_per_address` live entries are held for the client address key.
        address_full,
        // The browser-binding token is empty.
        no_browser_token,
        // The random source or the hash failed.
        secret_unavailable,
    };

    // Takes `authorisation`, bound to `browser_token`, for the browser at `client_address_key`, valid for
    // `lifetime_ms` from `now_ms`. Sets its `created_at_ms` and `client_address_key` and empties its `user_id`.
    // Returns the fresh identifier (`make_oauth_secret`, 64 hex digits), once, or why nothing was stored.
    [[nodiscard]] auto create(PendingAuthorisation authorisation, std::string_view browser_token,
                              std::string_view client_address_key, std::uint64_t now_ms)
        -> std::variant<std::string, Refusal>;

    // A copy of the live entry `identifier` names, when `browser_token` is the one it is bound to; otherwise nullopt,
    // the same for an unknown identifier and for a wrong token.
    [[nodiscard]] auto find(std::string_view identifier, std::string_view browser_token, std::uint64_t now_ms)
        -> std::optional<PendingAuthorisation>;

    // Records `user_id` as the user whose password was verified for the entry. False, changing nothing, when `find`
    // would answer nullopt. Does not extend the entry's lifetime.
    [[nodiscard]] auto record_user(std::string_view identifier, std::string_view browser_token,
                                   std::string_view user_id, std::uint64_t now_ms) -> bool;

    // Removes the entry and returns it, for an approval or a denial; nullopt, removing nothing, when `find` would
    // answer nullopt (a wrong token does not spend the entry).
    [[nodiscard]] auto consume(std::string_view identifier, std::string_view browser_token, std::uint64_t now_ms)
        -> std::optional<PendingAuthorisation>;

    // How many live entries name `client_id`, after removing the expired ones. No scan.
    [[nodiscard]] auto live_count_for_client(std::string_view client_id, std::uint64_t now_ms) -> std::size_t;

    // Whether a live entry names `client_id`, without changing the store. O(1): the latest expiry held for the client.
    [[nodiscard]] auto holds_live_entry_for_client(std::string_view client_id, std::uint64_t now_ms) const -> bool;

    // Removes every entry whose lifetime ended at or before `now_ms`.
    auto erase_expired(std::uint64_t now_ms) -> void;

    // Entries held, expired ones not yet removed included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        PendingAuthorisation authorisation{};
        std::string browser_token_hash{};
        std::uint64_t expires_at_ms{0U};
    };

    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, database::detail::StateGroupKeyHash, std::equal_to<>>;

    // The live entry `identifier` names when `browser_token` matches its binding, or nullptr. Removes expired entries
    // first. Valid until the next change.
    [[nodiscard]] auto bound_entry(std::string_view identifier, std::string_view browser_token, std::uint64_t now_ms)
        -> std::pair<Entry*, std::string>;
    // Drops an entry that left the table from the per-address and per-client counters.
    auto forget(Entry const& entry) -> void;

    HashedSecretTable<Entry> m_entries{};
    KeyedBy<std::size_t> m_count_by_address{};
    // client_id -> the expiry of each of its entries; the last element is the latest.
    KeyedBy<std::multiset<std::uint64_t>> m_expiries_by_client{};
};

} // namespace merovingian::homeserver
