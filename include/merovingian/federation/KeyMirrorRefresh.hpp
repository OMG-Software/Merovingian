// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::federation
{

// Whether a resolver that finds no usable cached key first re-reads that
// server's key rows from the database. A federation worker's in-memory mirror
// is a snapshot taken when it started, so a key main cached afterwards is
// invisible to it; `on_miss` lets it read the row main verified and persisted
// instead of fetching the key again over a fresh connection. Public columns
// only (`database::refresh_remote_signing_keys`). Main's mirror is
// authoritative, so main leaves this `never`.
enum class KeyMirrorRefresh
{
    never,
    on_miss,
};

} // namespace merovingian::federation
