// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/AuthorizationGrant.hpp"
#include "merovingian/homeserver/HashedSecretTable.hpp"

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

// The authorisation codes minted by approvals and not yet expired (plan P5, "The authorisation flow" steps 5 and 6,
// ADR-0782). In memory only: a code lives 60 seconds, and a restart only makes the client start its login again.
//
// A code is a fresh 256-bit secret, returned once by `issue`; only its hash is kept, found through a digest index and
// confirmed in constant time (`HashedSecretTable`). Redemption is single use. A redeemed code stays remembered, marked
// redeemed, until its own expiry, so that a second presentation is recognised as a replay and names the session the
// first one produced (RFC 6749 section 4.1.2: a code used twice MUST be refused and SHOULD revoke the tokens it gave).
//
// Bounded: `max_codes` in all, redeemed ones included. At the cap the expired codes are purged and, if it is still
// full, the issue is refused; a live code is never evicted. Every operation takes the current time. Not thread-safe:
// `runtime.mutex` serialises every use (the store is `HomeserverRuntime::oauth_codes`).
class AuthorizationCodeStore final
{
public:
    // A code is valid this long from its issue (RFC 6749 section 4.1.2 recommends at most ten minutes; the client
    // redeems it at once, so 60 seconds leaves room for a slow network and little for a stolen code).
    static constexpr auto lifetime_ms = std::uint64_t{60'000U};
    // At most this many codes, redeemed ones included: a code is minted only after a verified password and an
    // approval, so this is far above honest use, and it bounds the retention sweep's walk (ADR-0782).
    static constexpr auto max_codes = std::size_t{8192U};

    enum class Refusal : std::uint8_t
    {
        // `max_codes` live codes are held.
        store_full,
        // The random source or the hash failed.
        secret_unavailable,
    };

    // Mints a code for `grant`, valid for `lifetime_ms` from `now_ms`. Returns the code (`make_oauth_secret`, 64 hex
    // digits), once, or why nothing was stored.
    [[nodiscard]] auto issue(AuthorizationGrant grant, std::uint64_t now_ms) -> std::variant<std::string, Refusal>;

    // Redeems `code` at `now_ms`: `fresh` the first time (and the code is spent), `replayed` every later time until
    // the code's own expiry, `unknown` otherwise.
    [[nodiscard]] auto redeem(std::string_view code, std::uint64_t now_ms) -> AuthorizationCodeRedemption;

    // The `created_at_ms` for the `oauth_sessions` row a grant from a code is about to write: `now_ms`, or one more
    // than the last value this store gave if that is not less. Strictly increasing over the store's life, so the value
    // recorded for a code names one row: a later grant on the same device ID, whose row replaces it, has another
    // (ADR-0792). Codes live in memory only, so uniqueness within the process is all a replay needs.
    [[nodiscard]] auto next_session_created_at_ms(std::uint64_t now_ms) noexcept -> std::uint64_t;

    // Records that the redemption of `code` issued the session whose row has `session_created_at_ms`, so a replay
    // names it. False, recording nothing, when `code` is not held as a redeemed code at `now_ms` (it expired since,
    // or was never redeemed) or already has a session recorded.
    [[nodiscard]] auto record_issued_session(std::string_view code, std::uint64_t session_created_at_ms,
                                             std::uint64_t now_ms) -> bool;

    // How many live, unredeemed codes name `client_id`, after removing the expired ones. No scan.
    [[nodiscard]] auto unredeemed_count_for_client(std::string_view client_id, std::uint64_t now_ms) -> std::size_t;

    // Whether a live, unredeemed code names `client_id`, without changing the store. O(1).
    [[nodiscard]] auto holds_unredeemed_code_for_client(std::string_view client_id, std::uint64_t now_ms) const -> bool;

    // Removes every code whose lifetime ended at or before `now_ms`.
    auto erase_expired(std::uint64_t now_ms) -> void;

    // Codes held, redeemed and expired ones not yet removed included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        AuthorizationGrant grant{};
        std::uint64_t expires_at_ms{0U};
        bool redeemed{false};
        // The session row the redemption issued, once recorded.
        std::optional<std::uint64_t> session_created_at_ms{};
    };

    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, database::detail::StateGroupKeyHash, std::equal_to<>>;

    // Drops an unredeemed code from the per-client expiries.
    auto forget_unredeemed(Entry const& entry) -> void;

    HashedSecretTable<Entry> m_codes{};
    // client_id -> the expiry of each of its unredeemed codes; the last element is the latest.
    KeyedBy<std::multiset<std::uint64_t>> m_unredeemed_expiries_by_client{};
    // The last value next_session_created_at_ms gave.
    std::uint64_t m_last_session_created_at_ms{0U};
};

} // namespace merovingian::homeserver
