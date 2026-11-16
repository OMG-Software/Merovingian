// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::homeserver
{

// The cross-signing reset approvals the account page grants (`org.matrix.cross_signing_reset`, ADR-0797): one per user,
// in memory, valid `lifetime_ms` from the approval, and spent by exactly one replacing upload of
// `POST /keys/device_signing/upload` from an OAuth session (the `m.oauth` UIA stage). A restart forgets every approval,
// which only means the user approves again.
//
// The upload takes the approval (`take`) before it stores the keys and gives it back (`restore`) when the store failed,
// so a failed store does not spend it and two concurrent uploads cannot both use one approval: `runtime.mutex`
// serialises every use, and the second upload finds nothing to take.
//
// Bounded at `max_approvals`; expired approvals are removed at the start of every operation, soonest first, at the cost
// of those removed. Every operation takes the current time, so a test needs no clock.
class CrossSigningResetApprovals final
{
public:
    // The spec's example ("the user can approve the reset for a limited time") leaves the time open; ten minutes lets a
    // person switch back to the application and retry, and is short enough that a forgotten approval lapses.
    static constexpr auto lifetime_ms = std::uint64_t{600'000U};
    // At most this many users with an approval at once. Each one needed a signed-in account-page session, itself
    // bounded at 4096 (`AccountSessionStore::max_sessions`).
    static constexpr auto max_approvals = std::size_t{4096U};

    // Records an approval for `user_id` valid until `now_ms + lifetime_ms`, replacing any the user holds. False, with
    // nothing recorded, for an empty user ID or at `max_approvals` approvals of other users.
    [[nodiscard]] auto approve(std::string_view user_id, std::uint64_t now_ms) -> bool;

    // Whether `user_id` holds a live approval.
    [[nodiscard]] auto holds(std::string_view user_id, std::uint64_t now_ms) -> bool;

    // Removes the user's live approval and returns its expiry, or nullopt when there is none.
    [[nodiscard]] auto take(std::string_view user_id, std::uint64_t now_ms) -> std::optional<std::uint64_t>;

    // Gives back an approval `take` returned, unless it has expired since or the user approved again meanwhile.
    auto restore(std::string_view user_id, std::uint64_t expires_at_ms, std::uint64_t now_ms) -> void;

    // Removes the user's approval, live or not (a password change, a deactivation).
    auto withdraw(std::string_view user_id) -> void;

    // Removes every approval whose lifetime ended at or before `now_ms`.
    auto erase_expired(std::uint64_t now_ms) -> void;

    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    using ExpiryIndex = std::multimap<std::uint64_t, std::string>;

    struct Approval final
    {
        std::uint64_t expires_at_ms{0U};
        ExpiryIndex::iterator expiry{};
    };

    auto record(std::string_view user_id, std::uint64_t expires_at_ms) -> void;

    std::unordered_map<std::string, Approval, database::detail::StateGroupKeyHash, std::equal_to<>> m_by_user{};
    // expiry -> user, soonest first, so `erase_expired` costs only what it removes.
    ExpiryIndex m_by_expiry{};
};

} // namespace merovingian::homeserver
