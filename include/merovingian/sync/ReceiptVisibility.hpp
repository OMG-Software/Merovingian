// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::sync
{

// Decides whether a stored receipt may appear in an `m.receipt` ephemeral event delivered
// to `viewer`. Shared by `/sync` and sliding sync so both surfaces apply one rule.
//
// Spec (client-server-api.md, "Receipts"):
//   - `m.read` is public: every member sees it.
//   - `m.read.private`: "Servers MUST NOT send the `m.read.private` receipt to any other
//     user than the one which originally sent it."
//   - `m.fully_read`: "does not appear under `m.receipt`". The marker is room account data
//     owned by its user, so it is never part of an `m.receipt` event, not even for its owner.
//
// Any other receipt type is withheld from everyone, so a type this server does not
// understand can never leak.
[[nodiscard]] auto receipt_visible_to(std::string_view receipt_type, std::string_view receipt_owner,
                                      std::string_view viewer) noexcept -> bool;

} // namespace merovingian::sync
