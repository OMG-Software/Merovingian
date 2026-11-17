// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// Where a delayed event is in its life (migration 003, ADR-0824). `scheduled` waits for its time; the other three
// are final: `sent` became an event, `cancelled` was cancelled by its owner, `failed` was cancelled by the server
// because sending it failed (its row then holds the error). `DelayedEventStatusText.hpp` maps each to the text the
// `status` column holds.
enum class DelayedEventStatus
{
    scheduled,
    sent,
    cancelled,
    failed,
};

} // namespace merovingian::database
