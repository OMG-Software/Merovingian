// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/EventStateGroupTable.hpp" // split-shim
#include "merovingian/database/StateGroupEntryTable.hpp" // split-shim
#include "merovingian/database/StateGroupTable.hpp"      // split-shim

// The in-memory mirrors of the three state-group tables (ADR-0064, ADR-0325): `state_groups`,
// `state_group_state` and `event_state_groups`. Each owns its rows and keeps a hash index over them,
// so a lookup by key costs the key's rows, never a pass over every room's rows on the server. This
// is the pattern `EventTable` set (ADR-0215, ADR-0300):
//
//   - the rows are exposed read-only (iteration, size, operator[]), so a reader that walks the whole
//     table still compiles;
//   - every change goes through the table's own insert / erase_if / clear, so a writer cannot
//     bypass the index (a direct `push_back` or `erase` does not compile);
//   - the indexes hold positions in the row vector, never iterators or pointers, so they survive its
//     reallocation.
//
// Iterating a table visits rows in the order they were added. Nothing is persisted here: hydration
// and reload_room fill the tables and the indexes come with the rows.
//
// THREAD SAFETY. A table has no lock; it is guarded by whatever guards the PersistentStore that owns
// it (`runtime.mutex` in the homeserver). A write reallocates the row vector and may rehash the
// index, and the three tables are changed one after another (reload_room), so a reader needs the
// same exclusion from writers that it needed for the `std::vector`s these replaced. The views and
// `std::string_view` results below point into the rows and are valid only until the next write.
