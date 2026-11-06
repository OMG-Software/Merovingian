// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// Outcome of store_global_account_data_within_cap and store_room_account_data_within_cap.
enum class CappedAccountDataStore
{
    stored,
    // The user already holds the cap's number of other types in the row's scope; nothing was
    // written.
    over_cap,
    // The row's content is over `max_account_data_row_bytes`; nothing was written.
    too_large,
    // A row of the wrong scope (room_id set for a global store, empty for a room store), a
    // missing user or type, or the write failed.
    failed,
};

} // namespace merovingian::database
