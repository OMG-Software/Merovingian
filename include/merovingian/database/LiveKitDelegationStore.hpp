// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentLiveKitDelegation.hpp"

#include <string_view>

namespace merovingian::database
{

struct PersistentStore;

// The LiveKit delegations of migration 004 (ADR-0832). Every function here reads or writes
// `PersistentStore::livekit_delegations` and, for a write, the database in one transaction with bound parameters
// only. Memory changes only after the commit returns true. None takes a lock; in main the caller holds
// `runtime.mutex`. The caps are in LiveKitDelegationTable.hpp.

// Stores `row` as the one delegation of its (user, room, slot, member): in one transaction the row holding the same
// key, if any, and the row holding the same delay ID, if any, are deleted and `row` is inserted (MSC4195: one
// delegation per key, and a new delay ID replaces the old). False, writing nothing, when a field is empty, over its
// cap or holds a NUL byte, or the commit fails.
[[nodiscard]] auto store_livekit_delegation(PersistentStore& store, PersistentLiveKitDelegation row) -> bool;

// Deletes the delegation of `delay_id`. True when the row is gone, also when there was none; false only when the
// commit fails, with memory unchanged.
[[nodiscard]] auto delete_livekit_delegation(PersistentStore& store, std::string_view delay_id) -> bool;

// Deletes every delegation of `user_id`. Always runs the DELETE, even when memory holds no row for the user: a row that
// hydration skipped is in the database and must not survive a deactivation. False only when the commit fails, with
// memory unchanged.
[[nodiscard]] auto delete_livekit_delegations_of_user(PersistentStore& store, std::string_view user_id) -> bool;

} // namespace merovingian::database
