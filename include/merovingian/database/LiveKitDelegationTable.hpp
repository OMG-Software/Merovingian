// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentLiveKitDelegation.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// Caps on what one row holds, enforced where the row is stored and where it is read back: an oversized row is
// refused, never truncated.
inline constexpr auto max_livekit_delegation_delay_id_bytes = std::size_t{64U};
// The user, room, slot and member IDs.
inline constexpr auto max_livekit_delegation_field_bytes = std::size_t{255U};

// Whether `row` may be stored: every text field non-empty, within its cap and free of NUL (PostgreSQL TEXT cannot hold
// one and the table's key joins its parts with one).
[[nodiscard]] auto livekit_delegation_is_storable(PersistentLiveKitDelegation const& row) noexcept -> bool;

// The in-memory copy of `livekit_delegations` (migration 004, ADR-0832). The class owns the rows and shows them
// read-only, so a writer that bypasses it does not compile and its indexes cannot drift from the rows. Indexes: by
// delay ID, by (user, room, slot, member) and a row count per user; the rows themselves are kept in insertion order.
// An erase renumbers the positions the two lookups hold, which costs the table's size; delegations are few and end
// rarely. The table has no lock: a reader needs exclusion from writers (in main, `runtime.mutex`). A pointer it
// returns is valid until the next write. Copy and move are defaulted: the indexes hold positions into the vector, so
// they stay valid in the copy.
class LiveKitDelegationTable final
{
public:
    // The row for `delay_id`, or nullptr.
    [[nodiscard]] auto find(std::string_view delay_id) const -> PersistentLiveKitDelegation const*;
    // The row of (`user_id`, `room_id`, `slot_id`, `member_id`), or nullptr.
    [[nodiscard]] auto find_by_key(std::string_view user_id, std::string_view room_id, std::string_view slot_id,
                                   std::string_view member_id) const -> PersistentLiveKitDelegation const*;
    // How many rows `user_id` holds.
    [[nodiscard]] auto count_of_user(std::string_view user_id) const -> std::size_t;
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return m_rows.size();
    }
    // Every row, in insertion order.
    [[nodiscard]] auto rows() const noexcept -> std::vector<PersistentLiveKitDelegation> const&
    {
        return m_rows;
    }

    // The remaining members are for the store functions (LiveKitDelegationStore.hpp) and hydration only.

    // Adds `row`. False, and nothing changes, when it is not storable (`livekit_delegation_is_storable`), its delay ID
    // is held or another row holds the same key.
    auto insert(PersistentLiveKitDelegation row) -> bool;
    // Removes the row for `delay_id`. False when absent.
    auto erase(std::string_view delay_id) -> bool;
    // Removes the row holding the key. False when absent.
    auto erase_key(std::string_view user_id, std::string_view room_id, std::string_view slot_id,
                   std::string_view member_id) -> bool;
    // Removes every row of `user_id`, returning how many.
    auto erase_user(std::string_view user_id) -> std::size_t;
    // Removes every row, for hydration.
    auto clear() noexcept -> void;

private:
    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, detail::StateGroupKeyHash, std::equal_to<>>;

    auto erase_at(std::size_t position) -> void;
    // Rebuilds both position indexes from the rows.
    auto reindex() -> void;

    std::vector<PersistentLiveKitDelegation> m_rows{};
    // Delay ID -> position in `m_rows`.
    KeyedBy<std::size_t> m_by_delay_id{};
    // (user NUL room NUL slot NUL member) -> position in `m_rows`.
    KeyedBy<std::size_t> m_by_key{};
    KeyedBy<std::size_t> m_user_counts{};
};

} // namespace merovingian::database
