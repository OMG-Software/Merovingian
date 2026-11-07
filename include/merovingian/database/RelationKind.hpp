// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// The `rel_type` of an event's `content."m.relates_to"` that the server aggregates
// (client-server-api.md, "Aggregations of child events"). Any other `rel_type`, `m.annotation`
// included ("not aggregated by the server"), is not indexed at all.
enum class RelationKind : unsigned char
{
    replace,
    thread,
    reference,
};

} // namespace merovingian::database
