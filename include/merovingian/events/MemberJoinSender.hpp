// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

namespace merovingian::events
{

// True for an m.room.member event with membership `join` whose `sender` differs from its `state_key`: one user claiming
// to join another. Refused where a remote event is admitted, never inside the auth rules (ADR-0612).
[[nodiscard]] auto join_names_another_user(canonicaljson::Value const& event) -> bool;

} // namespace merovingian::events
