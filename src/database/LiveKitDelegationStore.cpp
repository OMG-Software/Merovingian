// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/LiveKitDelegationStore.hpp"

#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/LiveKitDelegationTable.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <string>
#include <tuple>
#include <utility>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto text(std::string_view value) -> BoundValue
    {
        return {std::string{value}, false};
    }

} // namespace

auto store_livekit_delegation(PersistentStore& store, PersistentLiveKitDelegation row) -> bool
{
    if (!livekit_delegation_is_storable(row))
    {
        return false;
    }
    auto const same_key = PreparedStatement{
        "delete_livekit_delegation_by_key",
        "DELETE FROM livekit_delegations WHERE user_id = $1 AND room_id = $2 AND slot_id = $3 AND member_id = $4",
        {text(row.user_id), text(row.room_id), text(row.slot_id), text(row.member_id)}
    };
    auto const same_delay_id = PreparedStatement{"delete_livekit_delegation_by_delay_id",
                                                 "DELETE FROM livekit_delegations WHERE delay_id = $1",
                                                 {text(row.delay_id)}};
    auto const insert = PreparedStatement{
        "insert_livekit_delegation",
        "INSERT INTO livekit_delegations (delay_id, user_id, room_id, slot_id, member_id, created_ms) VALUES ($1, $2, "
        "$3, $4, $5, $6)",
        {text(row.delay_id), text(row.user_id), text(row.room_id), text(row.slot_id), text(row.member_id),
          text(std::to_string(row.created_ms))}
    };
    if (!commit_persistent_transaction(store, {same_key, same_delay_id, insert}))
    {
        return false;
    }
    std::ignore = store.livekit_delegations.erase_key(row.user_id, row.room_id, row.slot_id, row.member_id);
    std::ignore = store.livekit_delegations.erase(row.delay_id);
    return store.livekit_delegations.insert(std::move(row));
}

auto delete_livekit_delegation(PersistentStore& store, std::string_view delay_id) -> bool
{
    // Always the DELETE: a row that hydration skipped is in the database and is removed with the rest.
    auto const statement = PreparedStatement{
        "delete_livekit_delegation", "DELETE FROM livekit_delegations WHERE delay_id = $1", {text(delay_id)}};
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.livekit_delegations.erase(delay_id);
    return true;
}

auto delete_livekit_delegations_of_user(PersistentStore& store, std::string_view user_id) -> bool
{
    auto const statement = PreparedStatement{
        "delete_livekit_delegations_of_user", "DELETE FROM livekit_delegations WHERE user_id = $1", {text(user_id)}};
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.livekit_delegations.erase_user(user_id);
    return true;
}

} // namespace merovingian::database
