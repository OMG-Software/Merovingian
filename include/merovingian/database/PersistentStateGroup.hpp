// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once


#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::database
{

// A state group (ADR-0064, docs/adr/0064-spec-conformant-pdu-ingestion-with-
// delta-state-groups.md): the room state after some event, stored either as
// a full snapshot (`parent_state_group_id == nullopt`, `delta_depth == 0`)
// or as a delta from `parent_state_group_id` (`delta_depth` = parent's
// depth + 1, capped at `events::max_state_group_delta_depth`). The group's
// own rows (the full state for a snapshot, or just the changed entries for a
// delta) live in `state_group_state`/`PersistentStateGroupStateEntry`, keyed
// by `state_group_id`. See database::create_or_reuse_state_group and
// database::read_state_group_full_state.
struct PersistentStateGroup final
{
    std::string state_group_id{};
    std::string room_id{};
    std::optional<std::string> parent_state_group_id{};
    std::uint32_t delta_depth{0U};
};

} // namespace merovingian::database
